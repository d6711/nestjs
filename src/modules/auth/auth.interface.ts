export interface ILoginResponse {
    accessToken: string;
    expiresAt: number;
    tokenType: string;
    crsfToken: string;
}
export interface IJwtPayload {
    sub: string;
    exp: number;
    iat: number;
}
