import md5 from 'md5';
import { authenticate, JWTSpecs, UserProvider } from '../src/core/auth';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';

jest.mock('speakeasy', () => ({
  totp: {
    verify: jest.fn(),
  },
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'jwt-token'),
}));

const mockedSpeakeasy = speakeasy as any;
const mockedJwt = jwt as any;

describe('authenticate', () => {
  const login = 'user@example.com';
  const password = 'strong-password';
  const userPassword = md5(password);
  const userMfa = { enabled: true, secret: { actual: 'BASE32SECRET' } };

  const jwtSpecs: JWTSpecs = {
    secretKey: 'jwt-secret',
    expiryTimeMs: 1000,
    refreshExpiryTimeMs: 2000,
  };

  let userProvider: UserProvider;
  let impersonateProvider: any;

  beforeEach(() => {
    mockedSpeakeasy.totp.verify.mockReset();
    mockedSpeakeasy.totp.verify.mockReturnValue(true);
    mockedJwt.sign.mockClear();

    userProvider = {
      getUser: jest.fn(async () => ({
        id: 'user-1',
        login,
        password: userPassword,
        mfa: userMfa,
      })),
      putUser: jest.fn(async () => undefined),
    };

    impersonateProvider = {
      canImpersonate: jest.fn(async () => false),
      impersonateOrg: jest.fn(async () => undefined),
    };
  });

  it('rejects when MFA is enabled but token is empty', async () => {
    mockedSpeakeasy.totp.verify.mockReturnValue(false);

    await expect(
      authenticate(login, password, '', '', userProvider, impersonateProvider, jwtSpecs),
    ).rejects.toThrow(`Failed authentication attempt ${login} (MFA Enabled)`);

    expect(mockedSpeakeasy.totp.verify).toHaveBeenCalledWith({
      secret: userMfa.secret.actual,
      encoding: 'base32',
      token: '',
      window: 1,
    });
  });

  it('returns tokens when password and MFA token are valid', async () => {
    mockedSpeakeasy.totp.verify.mockReturnValue(true);

    const result = await authenticate(
      login,
      password,
      '123456',
      '',
      userProvider,
      impersonateProvider,
      jwtSpecs,
    );

    expect(result).toEqual({
      token: 'jwt-token',
      refreshToken: 'jwt-token',
    });
    expect(mockedJwt.sign).toHaveBeenCalled();
    expect((userProvider.getUser as jest.Mock).mock.calls[0][0]).toBe(login);
  });
});
