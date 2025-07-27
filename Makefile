help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-21s\033[0m %s\n", $$1, $$2}'

install-deps: ## Install python dependencies for development
	uv sync

format: ## Format the code according to the standards
	uv run ruff check --fix .
	uv run ruff format .