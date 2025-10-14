# Pico Auth

Pico Auth is a minimal authentication library that provides user/password authentication, multi-factor authentication (MFA), and impersonation capabilities.

## Installation

```sh
npm install pico-auth
```

## Usage

### Main Methods

#### `authenticate`

Authenticates a user with login, password, and optionally an MFA token and impersonation entity.

```ts
import { authenticate } from 'pico-auth';

const tokens = await authenticate(login, password, mfaToken, impersonateEntity, userProvider, impersonateProvider, jwtSpecs);
```

- `login`: The user's login.
- `password`: The user's password.
- `mfaToken`: The MFA token (optional).
- `impersonateEntity`: The entity to impersonate (optional).
- `userProvider`: An object implementing the `UserProvider` interface.
- `impersonateProvider`: An object implementing the `ImpersonateProvider` interface.
- `jwtSpecs`: An object containing JWT specifications.
- `tokens`: An returned object containing fields: short lived `token` and long lived `refreshToken`

#### `refreshToken`

Refresh token when new short lived token is requested

```ts
import { refreshToken } from 'pico-auth';

const token = await refreshToken(login, refreshToken, userProvider, jwtSpecs);
```

- `login`: The user's login.
- `userProvider`: An object implementing the `UserProvider` interface.
- `jwtSpecs`: An object containing JWT specifications.
- `token`: An returned object containing field: short lived `token`

#### `mfaRegister`

Prepares a user for MFA activation by generating a secret and a QR code.

```ts
import { mfaRegister } from 'pico-auth';

const { qr_code, secret } = await mfaRegister(appName, login, userProvider);
```

- `appName`: The name of the application.
- `login`: The user's login.
- `userProvider`: An object implementing the `UserProvider` interface.

#### `mfaVerify`

Verifies the MFA token and fully initializes MFA for the user if the token is valid.

```ts
import { mfaVerify } from 'pico-auth';

const isVerified = await mfaVerify(login, mfaToken, userProvider);
```

- `login`: The user's login.
- `mfaToken`: The MFA token.
- `userProvider`: An object implementing the `UserProvider` interface.

#### `mfaEnabled`

Checks if MFA is enabled for a user.

```ts
import { mfaEnabled } from 'pico-auth';

const isEnabled = await mfaEnabled(login, userProvider);
```

- `login`: The user's login.
- `userProvider`: An object implementing the `UserProvider` interface.

### Types

#### `UserProvider`

An interface for user-related operations.

```ts
interface UserProvider {
    getUser(login: string): Promise<BaseUser>;
    putUser(user: any): Promise<any>;
    userSecretPath?: string;
    userPasswordPath?: string;
}
```

#### `ImpersonateProvider`

An interface for impersonation-related operations.

```ts
interface ImpersonateProvider {
    canImpersonate(user: any, target: string): Promise<any>;
    impersonateOrg(user: any, target: string): Promise<any>;
}
```

#### `JWTSpecs`

An interface for JWT specifications.

```ts
interface JWTSpecs {
    secretKey: string;
    expiryTimeMs: any;
}
```

#### `BaseUser`

An interface representing a basic user.

```ts
interface BaseUser {
    blocked?: boolean;
    [key: string]: any;
}
```

## License

This project is licensed under the MIT License.