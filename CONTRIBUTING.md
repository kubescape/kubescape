# Contributing

First, it is awesome that you are considering contributing to Kubescape! Contributing is important and fun and we welcome your efforts.

When contributing, we categorize contributions into two:
* Small code changes or fixes, whose scope is limited to a single or two files
* Complex features and improvements, with potentially unlimited scope

If you have a small change, feel free to fire up a Pull Request.

When planning a bigger change, please first discuss the change you wish to make via an issue,
so the maintainers are able to help guide you and let you know if you are going in the right direction.

## Code of Conduct

Please follow our [code of conduct](CODE_OF_CONDUCT.md) in all of your interactions within the project.

## Build and test locally

Please follow the [instructions here](https://github.com/kubescape/kubescape/wiki/Building).

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a 
   build.
2. Update the README.md with details of changes to the interface, this includes new environment 
   variables, exposed ports, useful file locations and container parameters.
3. Open Pull Request to the `master` branch.
4. We will merge the Pull Request once you have the sign-off.

## Developer Certificate of Origin

All commits to the project must be "signed off", which states that you agree to the terms of the [Developer Certificate of Origin](https://developercertificate.org/).  This is done by adding a "Signed-off-by:" line in the commit message, with your name and email address.

Commits made through the GitHub web application are automatically signed off.

### Configuring Git to sign off commits

First, configure your name and email address in Git global settings:

```
$ git config --global user.name "John Doe" 
$ git config --global user.email johndoe@example.com
```

You can now sign off per-commit, or configure Git to always sign off commits per repository.

### Sign off per-commit

Add [`-s`](https://git-scm.com/docs/git-commit#Documentation/git-commit.txt--s) to your Git command line. For example:

```git commit -s -m "Fix issue 64738"```

This is tedious, and if you forget, you'll have to [amend your commit](#fixing-a-commit-where-the-dco-failed).

### Configure a repository to always include sign off

There are many ways to achieve this with Git hooks, but the simplest is to do the following:

```
cd your-repo
curl -Ls https://gist.githubusercontent.com/dixudx/7d7edea35b4d91e1a2a8fbf41d0954fa/raw/prepare-commit-msg -o .git/hooks/prepare-commit-msg
chmod +x .git/hooks/prepare-commit-msg
```

### Use semantic commit messages (optional)

When contributing, you could consider using [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/), in order to improve logs readability and help us to automatically generate `CHANGELOG`s.

Format: `<type>(<scope>): <subject>`

`<scope>` is optional

#### Example

```
feat(cmd): add kubectl plugin
^--^ ^-^   ^----------------^
|    |     |
|    |     +-> subject: summary in present tense.
|    |
|    +-------> scope: point of interest
|
+-------> type: chore, docs, feat, fix, refactor, style, or test.
```

More Examples:
* `feat`: new feature for the user, not a new feature for build script
* `fix`: bug fix for the user, not a fix to a build script
* `docs`: changes to the documentation
* `style`: formatting, missing semi colons, etc; no production code change
* `refactor`: refactoring production code, eg. renaming a variable
* `test`: adding missing tests, refactoring tests; no production code change
* `chore`: updating grunt tasks etc; no production code change

## Fixing a commit where the DCO failed

Check out [this guide](https://github.com/src-d/guide/blob/master/developer-community/fix-DCO.md).
