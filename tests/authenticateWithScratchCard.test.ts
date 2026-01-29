import { authenticateWithScratchCard, JWTSpecs, UserProvider, ScratchCardProvider } from '../src/core/auth';
import * as authModule from '../src/core/auth';

describe('authenticateWithScratchCard', () => {
  const jwtSpecs: JWTSpecs = {
    secretKey: 'jwt-secret',
    expiryTimeMs: 1000,
    refreshExpiryTimeMs: 2000,
  };

  let userProvider: UserProvider;
  let scratchCardProvider: ScratchCardProvider;
  const cardCode = 'CARD-123';

  beforeEach(() => {
    jest.restoreAllMocks();

    userProvider = {
      getUser: jest.fn(async () => ({
        id: 'requester',
        login: 'requester@example.com',
        blocked: false,
      })),
      putUser: jest.fn(async () => undefined),
    };

    scratchCardProvider = {
      consume: jest.fn(),
    };
  });

  it('returns tokens and cleared user when scratch card authentication succeeds', async () => {
    const targetUser = { id: 'target-user', blocked: false, role: 'user' };
    (scratchCardProvider.consume as jest.Mock).mockResolvedValue(targetUser);

    const issueJwtTokenSpy = jest
      .spyOn(authModule, 'issueJwtToken')
      .mockResolvedValueOnce({ token: 'access-token', clearedUser: { id: 'cleared' } })
      .mockResolvedValueOnce({ token: 'refresh-token', clearedUser: { id: 'cleared' } });

    const result = await authenticateWithScratchCard(
      cardCode,
      userProvider,
      scratchCardProvider,
      jwtSpecs,
    );

    expect(result).toEqual({
      token: 'access-token',
      refreshToken: 'refresh-token',
      user: { id: 'cleared' },
    });
    expect(scratchCardProvider.consume).toHaveBeenCalledWith(cardCode, undefined);
    expect(issueJwtTokenSpy).toHaveBeenNthCalledWith(1, targetUser, userProvider, jwtSpecs, false);
    expect(issueJwtTokenSpy).toHaveBeenNthCalledWith(2, targetUser, userProvider, jwtSpecs, true);
  });

  it('rejects when target user is blocked after consuming scratch card', async () => {
    const blockedTarget = { id: 'target-user', blocked: true };
    (scratchCardProvider.consume as jest.Mock).mockResolvedValue(blockedTarget);

    const issueJwtTokenSpy = jest.spyOn(authModule, 'issueJwtToken');

    await expect(
      authenticateWithScratchCard(
        cardCode,
        userProvider,
        scratchCardProvider,
        jwtSpecs,
        'requester@example.com',
      ),
    ).rejects.toThrow('Failed card authentication attempt requester@example.com');

    expect(issueJwtTokenSpy).not.toHaveBeenCalled();
    expect(scratchCardProvider.consume).toHaveBeenCalledWith(cardCode, expect.objectContaining({ id: 'requester' }));
  });

  it('rejects when scratch card consumption fails', async () => {
    (scratchCardProvider.consume as jest.Mock).mockRejectedValue(new Error('consume failed'));

    await expect(
      authenticateWithScratchCard(
        cardCode,
        userProvider,
        scratchCardProvider,
        jwtSpecs,
        'requester@example.com',
      ),
    ).rejects.toThrow('Failed card authentication attempt requester@example.com (Consume Failed)');
  });
});
