.PHONY: run scan seed stop build

# Bring the app up on http://localhost:5050
run:
	docker compose up --build

build:
	docker compose build

stop:
	docker compose down

# Run Semgrep and emit SARIF. venv/__pycache__/node_modules excluded via .semgrepignore.
scan:
	semgrep scan --config auto --sarif --output report.sarif .

# Recreate the SQLite database with seed data.
seed:
	python -m app.db_init
