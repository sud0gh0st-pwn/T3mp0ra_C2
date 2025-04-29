# Tempora C2 Test Suite

This directory contains automated tests for the Tempora C2 server and client.

## Test Files

- `test_admin_commands.py`: Tests for the admin interface commands in the C2 server.
- `test_client_responses.py`: Tests for client responses to server commands.
- `test_payload_gen.py`: Tests for the payload generation functionality.
- `run_tests.py`: Script to run all tests.

## Running Tests

There are several ways to run the tests:

### Run all tests

```bash
# From the project root directory
python -m src.tests.run_tests
```

### Run a specific test file

```bash
# From the project root directory
python -m src.tests.test_admin_commands
python -m src.tests.test_client_responses
python -m src.tests.test_payload_gen
```

### Run a specific test case

```bash
# From the project root directory
python -m src.tests.test_admin_commands TestAdminCommands.test_list_command
```

## Test Coverage

The tests cover the following functionality:

### Admin Commands Tests

- Command parsing and execution
- Client listing and status reporting
- Target selection and client information display
- Task creation and dispatch
- Payload generation and sending

### Client Response Tests

- Heartbeat acknowledgment
- Shell command execution and response
- System information gathering
- Payload execution

### Payload Generation Tests

- Obfuscation at different levels
- Encryption and compression
- Anti-debugging and anti-VM detection
- Persistence mechanisms
- Network communication capabilities

## Adding New Tests

To add new tests:

1. Create a new file named `test_*.py` in this directory
2. Import the needed modules and classes
3. Create test case classes inheriting from `unittest.TestCase`
4. Define test methods starting with `test_`
5. Run the tests to ensure they work as expected

## Test Environment

These tests use Python's `unittest` framework and mock various components to avoid actual network connections or system changes. The tests are designed to be repeatable and isolated.

For real integration testing, you would need to set up a controlled environment with actual server and client instances.

## Note on Integration Tests

The `TestClientServerIntegration` class in `test_client_responses.py` contains commented-out integration tests that require actual network connections. These tests are provided as examples but are disabled by default to avoid unintended side effects. 