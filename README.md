# CyberAware - Scam Detection Tool

## Overview

CyberAware is a web-based security analysis tool designed to detect potential scams in SMS messages, URLs, and UPI requests. The application uses pattern matching and keyword analysis to identify suspicious content and provide users with security assessments. Built with Flask, it offers a simple yet effective solution for everyday users to validate suspicious digital communications.

## System Architecture

### Frontend Architecture
- **Framework**: Bootstrap 5.3.0 with custom CSS
- **JavaScript**: Vanilla JavaScript for form handling and UX enhancements
- **Template Engine**: Jinja2 (Flask's default)
- **Styling**: Custom CSS with CSS variables for theming, Google Fonts (Inter)
- **Icons**: Font Awesome 6.4.0
- **Responsive Design**: Mobile-first approach using Bootstrap's grid system

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Application Structure**: 
  - `main.py`: Entry point for production deployment
  - `app.py`: Flask application factory and route definitions
  - `analyzer.py`: Core security analysis logic
- **Session Management**: Flask's built-in session handling with secret key
- **Error Handling**: Try-catch blocks with user-friendly flash messages
- **Logging**: Python's logging module for debugging and monitoring

## Key Components

### Security Analyzer (`analyzer.py`)
- **Pattern Matching**: Regex patterns for URLs, phone numbers, and UPI IDs
- **Keyword Detection**: Comprehensive list of scam-related keywords
- **Domain Analysis**: Detection of suspicious domains and URL shorteners
- **Risk Assessment**: Scoring system for threat levels
- **Content Analysis**: Multi-faceted analysis of text content

### Web Interface (`app.py`)
- **Route Handling**: GET/POST endpoints for analysis and navigation
- **Form Processing**: Content validation and analysis request handling
- **Flash Messaging**: User feedback system for errors and warnings
- **Template Rendering**: Dynamic content rendering with analysis results

### Static Assets
- **CSS**: Custom styling with CSS variables for maintainable theming
- **JavaScript**: Client-side form validation and UX improvements
- **Templates**: HTML templates with Bootstrap components

## Data Flow

1. **User Input**: User submits content through web form
2. **Validation**: Client-side and server-side validation of input
3. **Analysis**: SecurityAnalyzer processes content using pattern matching
4. **Risk Assessment**: Content is scored and categorized by threat level
5. **Results Display**: Analysis results rendered in user-friendly format
6. **User Feedback**: Flash messages provide status updates and error handling

## External Dependencies

### Python Packages
- **Flask**: Web framework for application structure
- **email-validator**: Email validation functionality
- **flask-sqlalchemy**: Database ORM (configured but not actively used)
- **gunicorn**: WSGI server for production deployment
- **psycopg2-binary**: PostgreSQL adapter (configured but not actively used)

### Frontend Libraries
- **Bootstrap 5.3.0**: UI framework and responsive design
- **Font Awesome 6.4.0**: Icon library
- **Google Fonts**: Typography (Inter font family)

### Infrastructure
- **Deployment Platform**: Supports any Python-compatible cloud server
- **Package Manager**: Nix or pip for system and Python dependencies
- **Database**: PostgreSQL (available but not currently utilized)

## Deployment Strategy

### Development Environment
- **Local Development**: Flask development server with debug mode
- **Hot Reload**: Automatic restart on code changes
- **Debug Logging**: Comprehensive logging for development

### Production Deployment
- **Server**: Gunicorn WSGI server
- **Scaling**: Deployable to any cloud host with autoscaling support
- **Port Configuration**: Application runs on port 5000
- **Process Management**: Gunicorn handles multiple worker processes

### Configuration
- **Environment Variables**: Session secret key from environment
- **Fallback Values**: Development defaults for local testing

## Changelog

