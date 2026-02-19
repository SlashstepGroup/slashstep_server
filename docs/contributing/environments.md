# Environments
> [!WARNING]
> For end users, Slashstep Group only using the production environment. End users may encounter unexpected bugs in lower environments more frequently, which may degrade the experience. 

## Development
### Purpose of development environment
The `main` branch represents the development environment.

### Development environment security
* Only collaborators with write access can push to the development environment.
* All contributors must sign their commits prior to pushing to the `main` branch.
* All Rust tests, if applicable, must pass before pushing to the `main` branch.
* All contributors are required to use a pull request before pushing to the `main` branch.
* Non-maintainers must have their pull requests approved by a maintainer before pushing to the `main` branch.
* Force pushing is not allowed on the main branch.

### Development images
Whenever a contributor commits to the `main` branch, GitHub Actions creates a development image of Slashstep Server. This image is available at:
* `ghcr.io/slashstepgroup/slashstep_server:development`
* `ghcr.io/slashstepgroup/slashstep_server:main`

## Staging
### Purpose of staging environment
The staging environment is for quality assurance and user acceptance testing.

### Staging environment security
* All contributors without admin access must use GitHub Actions to deploy to the staging environment. Only collaborators with admin access can directly publish staging images; but, even then, admins should avoid deploying directly to preserve transparency.
* All staging deployments require approval from another collaborator with at least write access. Currently, due to a shortage of maintainers, the producer is exempt from this rule.

### Staging images
When a maintainer publishes a prerelease, then GitHub Actions creates a staging image of Slashstep Server. This image is available at:
* `ghcr.io/slashstepgroup/slashstep_server:staging`

## Production
### Purpose of production environment
The production environment is for end users. 

### Production environment security
* All contributors without admin access must use GitHub Actions to deploy to the production environment. Only collaborators with admin access can directly publish production images; but, even then, admins should avoid deploying directly to preserve transparency.
* All production deployments require approval from another collaborator with at least write access. Currently, due to a shortage of maintainers, the producer is exempt from this rule.

### Production images
> [!TIP]
> Slashstep Group recommends specifying the version-specific tags rather than relying on the named tags like "production" and "latest". This way, admins aren't surprised by unpredictable behavior.

When a maintainer publishes a release, then GitHub Actions creates a production image of Slashstep Server. This image is available at:
* `ghcr.io/slashstepgroup/slashstep_server:{version}`, where `{version}` is a version like "1.0.0". Refer to the releases for available versions.
* `ghcr.io/slashstepgroup/slashstep_server:production`
* `ghcr.io/slashstepgroup/slashstep_server:latest`
* `ghcr.io/slashstepgroup/slashstep_server`