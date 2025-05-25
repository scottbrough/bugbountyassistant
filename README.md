[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/scottbrough/bugbountyassistant)

# Bug Bounty Assistant

A comprehensive web application for automated bug bounty hunting with AI-powered vulnerability detection and real-time progress tracking.

## Features

### Core Functionality
- **Automated Reconnaissance**: Discover subdomains, endpoints, and potential vulnerabilities
- **AI-Powered Analysis**: Classify endpoints and generate targeted payloads
- **Real-time Progress Tracking**: Monitor hunt progress with Socket.IO live updates
- **Vulnerability Detection**: Identify common web vulnerabilities automatically
- **Report Generation**: Create detailed vulnerability reports

### Advanced Features

#### Authentication Support
- Add credentials for authenticated testing of targets
- Support for both form-based and JavaScript-heavy login pages
- Selenium-based authentication for complex sites
- Test for authenticated vulnerabilities like IDOR and privilege escalation

#### Endpoint Classification
- AI-powered classification of discovered endpoints
- Categorization by interest level (high/medium/low)
- Identification of potential vulnerability types
- Visualization of classified endpoints in the expanded hunt view

#### OpenAI Integration Optimization
- Batch processing with configurable batch size (default: 50)
- Rate limiting with configurable delays between API calls
- Token usage optimization (max 2000 tokens per request)
- Model selection for cost/performance balance

#### Advanced Configuration
- Customizable hunt parameters in the settings panel
- Batch size and rate limit delay configuration
- Maximum tokens per request settings
- Model selection options

## Getting Started

### Installation
```bash
git clone https://github.com/scottbrough/bugbountyassistant.git
cd bugbountyassistant
pip install -r requirements.txt
```

### Configuration
1. Set your OpenAI API key in the settings panel
2. Configure hunt parameters based on your needs
3. Add authentication credentials for targets requiring login

### Running a Hunt
1. Start the application: `python src/app.py`
2. Access the web interface at `http://localhost:5000`
3. Enter a target domain and configure hunt options
4. Start the hunt and monitor progress in real-time

## Usage Examples

### Adding Authentication for a Target
1. Start a hunt for your target
2. In the expanded hunt view, click "Add Auth"
3. Enter username, password, and optional login URL
4. Save credentials to enable authenticated testing

### Configuring OpenAI Settings
1. Open the settings panel
2. Adjust batch size (10-100) based on your needs
3. Set rate limit delay to avoid API throttling
4. Configure maximum tokens per request (1000-4000)

## Architecture

The application consists of:
- Flask backend with Socket.IO for real-time updates
- React-based frontend for interactive UI
- Authentication session manager for credential handling
- Advanced assistant for AI-powered vulnerability detection

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
