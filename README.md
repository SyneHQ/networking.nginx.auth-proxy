# Auth Proxy

An OpenResty/Nginx authentication proxy that validates Auth.js JWE tokens and provides user verification through Redis caching and PostgreSQL database checks.

## Why?

This auth proxy is useful when you have an access application using Next.js or other frontend frameworks that use Auth.js library to manage user sessions, and you want to share that authentication token with other applications in your stack - whether that's a Python application, Go REST API, or any other service.

By using this nginx proxy, you can put those applications behind an authentication layer that validates the same Auth.js session tokens your frontend uses, creating a unified authentication system across your entire application ecosystem.

### Common Use Cases

**Microservices Authentication**: Protect multiple backend services (Node.js APIs, Python Flask/FastAPI apps, Go services, etc.) with a single authentication layer without duplicating auth logic in each service.

**Legacy System Integration**: Add modern Auth.js authentication to legacy applications that don't have built-in session management by placing them behind this proxy.

**API Gateway Pattern**: Use as an authentication gateway for your API infrastructure, validating tokens before requests reach your backend services.

**Static Site Protection**: Secure static websites, documentation sites, or admin panels by requiring users to authenticate through your main application first.

**Multi-Language Environments**: Bridge authentication between different technology stacks - your React frontend can authenticate users while your Python data processing APIs, Go microservices, and PHP admin panels all share the same session validation.

**Development Environment**: Quickly add authentication to development tools, staging environments, or internal dashboards without implementing custom auth in each tool.

**Third-Party Integration**: Authenticate users for third-party services or self-hosted applications (like Grafana, Jenkins, or custom tools) using your existing Auth.js sessions.

## Features

- **JWT/JWE Token Validation**: Decrypts and validates Auth.js issued JWE tokens
- **Redis Caching**: Caches user validation results to reduce database load
- **PostgreSQL Integration**: Verifies user existence in configurable database tables
- **Environment Configuration**: Flexible configuration through environment variables
- **High Performance**: Built on OpenResty for optimal performance

## Configuration

The proxy is configured through environment variables:

### JWT Configuration
- `JWT_SECRET`: Secret key for JWT decryption (default: "your_secret")
- `JWT_SALT`: Salt for Auth.js session token (default: "authjs.session-token")

### Redis Configuration
- `REDIS_HOST`: Redis server host (default: "redis")
- `REDIS_PORT`: Redis server port (default: 6379)
- `REDIS_TIMEOUT`: Connection timeout in ms (default: 1000)
- `REDIS_CACHE_TTL`: Cache TTL in seconds (default: 600)
- `REDIS_PASSWORD`: Redis password (default: "")
- `REDIS_KEY_PREFIX`: Key prefix for cached entries (default: "auth:")

### PostgreSQL Configuration
- `POSTGRES_HOST`: PostgreSQL server host (default: "postgres")
- `POSTGRES_PORT`: PostgreSQL server port (default: "5432")
- `POSTGRES_DB`: Database name (default: "your_db")
- `POSTGRES_USER`: Database user (default: "your_user")
- `POSTGRES_PASSWORD`: Database password (default: "your_password")
- `USER_TABLE`: User table name (default: "users")
- `USER_ID_FIELD`: User ID field name (default: "id")

### Feature Flags
- `ENABLE_DB_CHECK`: Enable database user verification (default: "false")