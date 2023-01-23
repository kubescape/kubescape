# Kubescape workflows

Tag terminology: `v<major>.<minor>.<patch>`

## Developing process

Kubescape's main branch is `main`, any PR will be opened against the main branch.

### Opening a PR

When a user opens a PR, this will trigger some basic tests (units, license, etc.)

### Reviewing a PR

The reviewer/maintainer of a PR will decide whether the PR introduces changes that require running the E2E system tests. If so, the reviewer will add the `trigger-integration-test` label.

### Approving a PR

Once a maintainer approves the PR, if the `trigger-integration-test` label was added to the PR, the GitHub actions will trigger the system test. The PR will be merged only after the system tests passed successfully. If the label was not added, the PR can be merged. 

### Merging a PR

The code is merged, no other actions are needed


## Release process

Every two weeks, we will create a new tag by bumping the minor version, this will create the release and publish the artifacts. 
If we are introducing breaking changes, we will update the `major` version instead.

When we wish to push a hot-fix/feature within the two weeks, we will bump the `patch`.

### Creating a new tag
Every two weeks or upon the decision of the maintainers, a maintainer can create a tag.

The tag should look as follows: `v<A>.<B>.<C>-rc.D` (release candidate). 

When creating a tag, GitHub will trigger the following actions:
1. Basic tests - unit tests, license, etc.
2. System tests (integration tests). If the tests fail, the actions will stop here.
3. Create a new tag: `v<A>.<B>.<C>` (same tag just without the `rc` suffix)
4. Create a release
5. Publish artifacts
6. Build and publish the docker image (this is meanwhile until we separate the microservice code from the LCI codebase)
 
## Additional Information

The "callers" have the alphabetic prefix and the "executes" have the numeric prefix

## Screenshot

<img width="1469" alt="image" src="https://user-images.githubusercontent.com/64066841/212532727-e82ec9e7-263d-408b-b4b0-a8c943f0109a.png">