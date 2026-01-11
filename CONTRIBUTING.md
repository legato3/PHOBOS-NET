# Contributing to PROX_NFDUMP

Thank you for your interest in contributing to PROX_NFDUMP!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/legato3/PROX_NFDUMP.git
cd PROX_NFDUMP
```

2. Install dependencies:
```bash
apt-get install -y nfdump python3 python3-pip python3-dnspython
pip3 install flask maxminddb requests
```

3. Review the architecture:
- [docs/AGENTS.md](docs/AGENTS.md) - Comprehensive architecture guide
- [docs/WARP.md](docs/WARP.md) - Development workflow

## Code Style

- Follow Python PEP 8 style guidelines
- Use meaningful variable names
- Add docstrings to functions and classes
- Comment complex logic

## Testing

- Test with sample data in `sample_data/` directory
- Validate HTML with `scripts/test_html_validation.py`
- Test deployment with `scripts/deploy.sh`

## Documentation

- Update relevant documentation in `docs/` when making changes
- Update README.md for user-facing changes
- Keep [docs/AGENTS.md](docs/AGENTS.md) up to date for AI agents

## Submitting Changes

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Update documentation
5. Submit a pull request

## Questions?

Refer to the documentation in the `docs/` directory or open an issue on GitHub.
