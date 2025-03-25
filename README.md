# OpenRouter AI Bug Hunter Pro - Burp Suite Extension

A powerful Burp Suite extension that leverages AI capabilities through OpenRouter's API to enhance web application security testing. This extension integrates advanced AI models to analyze HTTP requests and responses, identify potential vulnerabilities, and provide detailed security insights.

## Features

- 🤖 **AI-Powered Analysis**: Utilizes OpenRouter's API to access various AI models for intelligent security analysis
- 🔍 **Comprehensive Scanning**: Supports both passive and active scanning modes
- 📊 **Customizable Templates**: Pre-built templates for different types of security analysis
- 📝 **Detailed Reporting**: Generates comprehensive reports of findings
- 🎯 **Custom Rules**: Create and manage custom scanning rules
- 🔄 **Real-time Analysis**: Automatic analysis of proxy traffic
- 📋 **History Management**: Track and review past analyses
- 🔐 **Secure Configuration**: Save and load API configurations securely

## Installation

1. Download the latest release of the extension
2. Open Burp Suite
3. Go to Extender > Extensions
4. Click "Add" and select the downloaded extension file
5. Configure your OpenRouter API key in the extension settings

## Configuration

1. Navigate to the "Configuration" tab
2. Enter your OpenRouter API key
3. Select your preferred AI model (default: google/gemini-pro)
4. Configure additional settings:
   - Auto-analysis
   - Scanner integration
   - Passive scanning
   - Rate limiting

## Usage

### Manual Analysis
1. Select a request from Proxy History, Target, or Repeater
2. Choose an analysis template or create a custom prompt
3. Click "Analyze with AI" to start the analysis
4. Review the results and add findings to the scanner if needed

### Automatic Analysis
1. Enable auto-analysis in the configuration
2. The extension will automatically analyze requests as they pass through the proxy
3. Review findings in the History tab

### Custom Rules
1. Navigate to the "Custom Rules" tab
2. Create new rules with custom patterns and prompts
3. Import/export rules as needed
4. Enable/disable rules for scanning

## Templates

The extension includes pre-built templates for various security scenarios:
- General Bug Hunting
- XSS Scanning
- SQL Injection
- Authentication Bypass
- Business Logic
- CSRF Vulnerabilities
- SSRF Detection
- JWT Analysis
- GraphQL Security

## Requirements

- Burp Suite Professional
- OpenRouter API key
- Java 8 or higher

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenRouter for providing the AI API
- Burp Suite team for the excellent framework
- All contributors and users of this extension

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 