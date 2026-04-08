# Contributing to On-Prem Network InfraIQ

Thank you for your interest in contributing to On-Prem Network InfraIQ! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Issues
1. **Search existing issues** before creating a new one
2. **Use the issue template** if available
3. **Provide clear reproduction steps** and system information
4. **Include relevant logs or screenshots**

### Submitting Changes
1. **Fork the repository**
2. **Create a feature branch** from `main`
3. **Make your changes** following our coding standards
4. **Test your changes** thoroughly
5. **Submit a pull request** with a clear description

## 🛠️ Development Setup

### Prerequisites
- .NET 8.0 SDK or later
- Git
- Your favorite C# IDE (Visual Studio, VS Code, Rider, etc.)
- Docker (optional, for containerized development)

### Local Development
```bash
# Clone your fork
git clone https://github.com/jomardyan/On-Prem-Network-InfraIQ.git
cd On-Prem-Network-InfraIQ

# Restore dependencies
dotnet restore

# Build the project
dotnet build --configuration Release

# Run the application
cd Discovery
dotnet run

# Run tests
dotnet test --configuration Release

# Run with Docker (optional)
docker build -t on-prem-network-infraiq .
docker run -it --rm --network host on-prem-network-infraiq
```

## 📝 Coding Standards

### Code Style
- Use **C# naming conventions** (PascalCase for public members, camelCase for private)
- Follow **.NET design guidelines**
- Use **async/await** for network operations
- Implement **proper resource disposal** with `using` statements
- Add **XML documentation** for public APIs

### Architecture Guidelines
- Keep **separation of concerns** between modules
- Use **dependency injection** where appropriate
- Follow the **existing project structure**:
  - `Core/` - Data models and constants
  - `Display/` - UI and presentation logic
  - `Tools/` - Network scanning and utilities

### Performance Considerations
- Use **concurrent collections** for thread-safe operations
- Implement **proper cancellation** with CancellationToken
- **Avoid blocking operations** in UI code
- **Dispose resources** properly

## 🧪 Testing

### Test Requirements
- Add **unit tests** for new functionality
- Ensure **existing tests pass**
- Test on **multiple platforms** (Windows, Linux, macOS)
- Verify **network operations** don't overwhelm targets

### Test Categories
- **Unit Tests** - Individual component testing
- **Integration Tests** - End-to-end functionality
- **Performance Tests** - Scalability and efficiency
- **Security Tests** - Vulnerability assessment accuracy

## 🔒 Security Guidelines

### Responsible Development
- **Never commit credentials** or sensitive data
- **Validate all user inputs** to prevent injection attacks
- **Follow security best practices** for network operations
- **Report security issues** privately to maintainers

### Ethical Considerations
- Ensure features promote **responsible usage**
- Add **appropriate warnings** for potentially harmful operations
- Include **rate limiting** to prevent abuse
- Document **legal and ethical usage** requirements

## 📋 Pull Request Process

### Before Submitting
1. **Update documentation** for new features
2. **Add or update tests** as needed
3. **Ensure code builds** without warnings
4. **Test on target platforms**
5. **Update CHANGELOG.md** if applicable

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)
Add screenshots of UI changes

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🎯 Areas for Contribution

### High Priority
- **IPv6 support** for modern networks
- **Performance optimizations** for large scans
- **Additional security checks** and vulnerability detection
- **Cross-platform compatibility** improvements

### Medium Priority
- **Database storage** for scan history
- **Configuration management** system
- **Plugin architecture** for extensibility
- **Advanced reporting** features

### Documentation
- **Code examples** and tutorials
- **API documentation** improvements
- **User guides** and best practices
- **Video tutorials** or demos

## 🐛 Bug Reports

### Include in Bug Reports
- **Operating system** and version
- **.NET version** (`dotnet --version`)
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Relevant logs or error messages**
- **Network configuration** if relevant

## 💡 Feature Requests

### Feature Request Guidelines
- **Describe the problem** the feature would solve
- **Explain the proposed solution**
- **Consider alternative approaches**
- **Discuss potential implementation** challenges
- **Ensure alignment** with project goals

## 📞 Getting Help

### Community Support
- **GitHub Discussions** - General questions and ideas
- **GitHub Issues** - Bug reports and feature requests
- **Documentation** - Check README.md and HELP.md first

### Maintainer Contact
- **Security issues** - Report privately to maintainers
- **Major contributions** - Discuss in GitHub Discussions first
- **Partnership opportunities** - Contact via GitHub

## 🙏 Recognition

Contributors are recognized in:
- **README.md** contributor section
- **Release notes** for significant contributions
- **Special thanks** in project documentation

## 📜 Code of Conduct

### Our Standards
- **Be respectful** and inclusive
- **Collaborate effectively** with others
- **Focus on constructive feedback**
- **Help maintain a positive** community environment

### Enforcement
- **Report violations** to project maintainers
- **Temporary or permanent bans** for serious violations
- **Appeals process** available for disputed actions

---

Thank you for contributing to On-Prem Network InfraIQ! Your efforts help make network security tools more accessible and effective for everyone.

**Questions?** Feel free to ask in GitHub Discussions or open an issue for clarification.
