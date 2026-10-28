# Authentication Service

A RESTful authentication service built with Java and Spring Boot, featuring JWT-based authentication, refresh token management, session control, and login security.

## Tech Stack

- **Language:** Java 17
- **Framework:** Spring Boot
- **Build Tool:** Maven
- **Database:** PostgreSQL
- **Database Migration:** Flyway
- **Authentication:** JSON Web Token (JWT)
- **Testing:** JUnit

## Features

- User registration
- User login using email or username
- JWT-based access token authentication
- Refresh token management
- Token revocation and logout
- Session management with one active session per user
- Login protection with configurable failed-attempt limits and temporary account lockout
- Database schema versioning with Flyway migrations
- Centralized exception handling

## Architecture

The application follows a layered architecture to separate responsibilities:

- **Controller:** Handles HTTP requests and responses.
- **Service:** Implements authentication and business logic.
- **Repository:** Handles database access.
- **Entity:** Represents persistent data.
- **Security:** Handles JWT authentication and request security.
- **Configuration:** Defines application and exception-handling configuration.

## Getting Started

### 1. Prerequisites

Before running the application, make sure you have:

- Java 17
- Maven, or use the included Maven Wrapper
- Docker
- PostgreSQL 17, or a compatible PostgreSQL instance

### 2. Clone the Project

git clone https://github.com/bernadetaratna/authentication-service.git
cd authentication-service

## Configuration

The application uses environment variables for database credentials and JWT signing configuration.

| Variable | Description |
|---|---|
| `DB_URL` | JDBC URL for PostgreSQL |
| `DB_USERNAME` | Database username |
| `DB_PASSWORD` | Database password |
| `APP_JWT_SECRET` | Base64-encoded JWT signing secret |

Refer to `.env.example` for the expected variable names and example values.

**Security note:** Replace all placeholder values with your own local configuration. Never commit actual passwords, signing secrets, or other credentials.

## Running Locally

1. Start a PostgreSQL instance and create the application database.
2. Configure the required environment variables in your IDE run configuration or shell.
3. Run the application

Flyway applies the database migrations during application startup. Hibernate validates the database schema against the entity mappings.

## API Endpoints

The application exposes authentication endpoints under the `/auth-service` context path.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/auth-service/api/authentication/user/register` | Register a new user |
| `POST` | `/auth-service/api/authentication/user/login` | Authenticate with email or username |
| `POST` | `/auth-service/api/authentication/user/refresh/token` | Refresh authentication tokens |
| `POST` | `/auth-service/api/authentication/user/logout` | Log out and revoke the relevant session or tokens |

The exact request and response formats are defined by the application's request and response models.

## Database Migrations

Flyway migration scripts are located in:

`src/main/resources/db/migration/`

The scripts define the database schema and seed the default roles.

## Author

**Bernadeta Ratna**

GitHub: [@bernadetaratna](https://github.com/bernadetaratna)
