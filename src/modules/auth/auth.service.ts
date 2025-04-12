import { Inject, Injectable, InternalServerErrorException, Logger, UnauthorizedException } from "@nestjs/common";
import { AuthRequest } from "./auth.request.dto";
import { PrismaService } from "../prisma/prisma.service";
import * as bcrypt from "bcrypt";
import { UserWithoutPassword } from "../users/user.interface";
import { IJwtPayload, ILoginResponse, ISessionData, ITokenContext } from "./auth.interface";
import { JwtService } from "@nestjs/jwt";
import { randomBytes } from "crypto";
import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Cache } from "cache-manager";
import { Request } from "express";
import { error } from "console";

const REFRESH_TOKEN_TIME_TO_LIVE = 30 * 24 * 60 * 3600
const MAX_SESSION_PER_USER = 5

@Injectable()
export class AuthService {

  private readonly logger = new Logger(AuthService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) { }

  async authenticate(authRequest: AuthRequest, request: Request): Promise<ILoginResponse> {
    try {
      return await this.createAuthContext(authRequest, request)
        .then(context => this.validateUser(context))
        .then(context => this.revokeExistingDeviceSession(context))
        .then(context => this.generateAccessToken(context))
        .then(context => this.generateRefreshToken(context))
        .then(context => this.generateCrsfToken(context))
        .then(context => this.saveSession(context))
        .then(context => this.authResponse(context))
    } catch (error) {
      if (error instanceof Error) {
        this.logger.error(`Lỗi trong quá trính xác thực: ${error.message}`, error.stack)
      }
      if (error instanceof UnauthorizedException) {
        throw error
      }
      throw new InternalServerErrorException('Có vấn đề xảy ra trong quá trình xác thực')
    }
  }

  private async createAuthContext(authRequest: AuthRequest, request: Request): Promise<ITokenContext> {
    return Promise.resolve({
      authRequest,
      user: null,
      deviceId: this.generateDeviceId(request)
    })
  }

  private generateDeviceId(request: Request): string {
    const userAgent = request.headers['user-agent'] || 'unknown'
    const ip = request.ip || 'unknown'
    return Buffer.from(`${userAgent}:${ip}`).toString('base64')
  }

  private async revokeExistingDeviceSession(context: ITokenContext): Promise<ITokenContext> {
    const { user, deviceId } = context
    if (!user || !deviceId) return context
    try {
      const userSession: string[] = await this.cacheManager.get(`user:${user.createdAt}:sessions`) || []
      let updateSession = [...userSession]
      for (let i = 0; i < userSession.length; i++) {
        const sessionId = userSession[i]
        const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}`)
        if (session && session.deviceId === deviceId) {
          session.isRevoked = true
          await this.cacheManager.set(`session:${sessionId}`, session)
          updateSession = updateSession.filter(id => id !== sessionId)
          this.logger.log(`Đã vô hiệu hóa phiên ${sessionId} trên thiết bị ${deviceId}`)
        }
      }
      if (updateSession.length !== userSession.length) {
        await this.cacheManager.set(`user:${user.id}:sessions`, updateSession)
      }
    } catch (error) {
      if (error instanceof Error) {
        this.logger.error(`Lỗi trong quá trính xác thực: ${error.message}`, error.stack)
      }
    }
    return context
  }
  private async generateAccessToken(context: ITokenContext): Promise<ITokenContext> {
    if (!context.user) throw new Error('Không có thông tin user trong context')
    const payload = { sub: context.user.id.toString() }
    context.accessToken = await this.jwtService.signAsync(payload)
    return context
  }
  private async generateRefreshToken(context: ITokenContext): Promise<ITokenContext> {
    context.refreshToken = randomBytes(32).toString('hex')
    return Promise.resolve(context)
  }
  private async generateCrsfToken(context: ITokenContext): Promise<ITokenContext> {
    context.crsfToken = randomBytes(32).toString('hex')
    return Promise.resolve(context)
  }
  private async saveSession(context: ITokenContext): Promise<ITokenContext> {
    const { user, deviceId, refreshToken, crsfToken } = context
    if (!user || !deviceId || !refreshToken || !crsfToken) throw new Error('Thiếu thông tin trong context để khởi tạo phiên đăng nhập')

    const sessionId = randomBytes(16).toString('hex')
    const sessionData: ISessionData = {
      userId: user.id.toString(),
      deviceId,
      refreshToken,
      crsfToken,
      creaedAt: Date.now(),
      lastUsed: Date.now(),
      wasUsed: false,
      isRevoked: false,
      expiresAt: Date.now() + REFRESH_TOKEN_TIME_TO_LIVE * 1000
    }
    const userSessions: string[] = (await this.cacheManager.get(`user:${user.id}:sessions`)) ?? []
    if (userSessions.length >= MAX_SESSION_PER_USER) {
      await this.removeOldesSession(user.id, userSessions)
    }
    await Promise.all([
      this.cacheManager.set(`session:${sessionId}`, sessionData, REFRESH_TOKEN_TIME_TO_LIVE),
      this.cacheManager.set(`refresh_token:${refreshToken}`, sessionId, REFRESH_TOKEN_TIME_TO_LIVE),
      this.cacheManager.set(`user:${user.id}:sessions`, [...userSessions, sessionId]),

    ])
    context.sessionId = sessionId
    return context
  }
  private async removeOldesSession(userId: bigint, sessions: string[]): Promise<void> {
    let oldesSessionId: string | null = null
    let oldesTimestamp = Infinity
    for (const sessionId of sessions) {
      const session: ISessionData | null = await this.cacheManager.get(`session:${sessionId}`)
      if (session && session.creaedAt < oldesTimestamp) {
        oldesTimestamp = session.creaedAt
        oldesSessionId = sessionId
      }
    }
    if (oldesSessionId) {
      const oldesSession: ISessionData | null = await this.cacheManager.get(`session:${oldesSessionId}`)
      if (oldesSession) {
        oldesSession.isRevoked = true
        await this.cacheManager.set(`session:${oldesSessionId}`, oldesSession)
        await this.cacheManager.set(`user:${userId}:sessions`, sessions.filter(id => id !== oldesSessionId))
      } else {
        this.logger.warn(`Không tìm thấy dữ liệu phiên cho sessionID ${oldesSessionId}`)
      }
    }

  }

  private async authResponse(context: ITokenContext): Promise<ILoginResponse> {
    const { accessToken, crsfToken } = context
    if (!accessToken || !crsfToken) throw new Error('Thiếu AccessToken hoặc CrsfToken trong Context')
    const decoded = this.jwtService.decode<IJwtPayload>(accessToken);
    const expiredAt = decoded.exp - Math.floor(Date.now() / 1000);
    return Promise.resolve({
      accessToken,
      crsfToken,
      expiresAt: expiredAt,
      tokenType: "Bearer",
    });
  }
  async validateUser(context: ITokenContext): Promise<ITokenContext> {
    const { email, password } = context.authRequest
    const user = await this.prismaService.user.findUnique({
      where: { email }
    });
    if (!user || !await bcrypt.compare(password, user.password))
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác');

    const { password: _, ...userWithoutPassword } = user;
    context.user = userWithoutPassword

    return context;
  }
}
