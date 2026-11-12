#!/bin/sh
# Runs IMAGE the way users do and checks it works: the container must pass its
# own health check, run as the unprivileged user, and serve signed requests:
# create an organization and an account in it, kept in the store on its
# volume.
set -eu

image=${1:?usage: run.sh IMAGE}
name=accounts-smoke-$$

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker logs "$name" || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker run -d --name "$name" -p 127.0.0.1::9020 \
	-e TULE_Auth_AccessKeyID=smoke -e TULE_Auth_SecretAccessKey=smoke \
	"$image" >/dev/null

# The health check first runs one interval (10s) after start.
health=
for _ in $(seq 60); do
	health=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$name")
	case $health in
	"running healthy") break ;;
	running*) sleep 1 ;;
	*) echo "container stopped: $health" >&2; exit 1 ;;
	esac
done
if [ "$health" != "running healthy" ]; then
	echo "container never became healthy: $health" >&2
	exit 1
fi

# The image must not run as root: it holds the store in its volume.
ids=$(docker exec "$name" id -u):$(docker exec "$name" id -g)
if [ "$ids" != 65532:65532 ]; then
	echo "runs as $ids, want 65532:65532" >&2
	exit 1
fi

addr=$(docker port "$name" 9020/tcp | head -n 1)

# Every call is a signed POST / naming the operation in X-Amz-Target, which is
# what the AWS JSON protocol the SDKs speak looks like on the wire.
org() {
	target=$1
	shift
	curl -fsS --aws-sigv4 aws:amz:us-east-1:organizations --user smoke:smoke \
		-H "Content-Type: application/x-amz-json-1.1" \
		-H "X-Amz-Target: AWSOrganizationsV20161128.$target" \
		--data-binary "$1" "http://$addr/"
}

created=$(org CreateOrganization '{"FeatureSet":"ALL"}')
case $created in
*'"MasterAccountId":"000000000000"'*) ;;
*)
	echo "created organization $created, want the default management account" >&2
	exit 1
	;;
esac

account=$(org CreateAccount '{"AccountName":"smoke","Email":"smoke@example.com"}')
case $account in
*'"State":"SUCCEEDED"'*) ;;
*)
	echo "created account $account, want SUCCEEDED" >&2
	exit 1
	;;
esac

listed=$(org ListAccounts '{}')
case $listed in
*'"Name":"smoke"'*) ;;
*)
	echo "listed accounts $listed, want the created one" >&2
	exit 1
	;;
esac

if ! docker exec "$name" test -s /data/accounts.db; then
	echo "no store at /data/accounts.db" >&2
	exit 1
fi

echo "smoke test passed: $image"
