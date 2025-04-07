import {
    Inject,
    Injectable,
    InternalServerErrorException,
    UnauthorizedException
} from "@nestjs/common";
import { AuthRequest } from "./auth.request.dto";
import { PrismaService } from "../prisma/prisma.service";
import * as bcrypt from "bcrypt";
import { UserWithoutPassword } from "../users/user.interface";
import { IJwtPayload, ILoginResponse } from "./auth.interface";
import { JwtService } from "@nestjs/jwt";
import { randomBytes } from "crypto";
import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Cache } from "cache-manager";
@Injectable()
export class AuthService {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly jwtService: JwtService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache
    ) {}
    async authenticate(request: AuthRequest): Promise<ILoginResponse> {
        try {
            const user = await this.validateUser(
                request.email,
                request.password
            );
            if (!user) {
                throw new UnauthorizedException(
                    "Email hoặc mật khẩu không chính xác"
                );
            }
            const payload = { sub: user.id.toString() };
            const accessToken = await this.jwtService.signAsync(payload);
            console.log(accessToken);
            const refreshToken = randomBytes(32).toString("hex");
            const crsfToken = randomBytes(32).toString("hex");
            console.log(refreshToken, crsfToken);

            await this.cacheManager.set("test", "123", 60000);
            return this.authResponse(accessToken, crsfToken);
        } catch (error) {
            throw new InternalServerErrorException(error);
        }
    }
    authResponse(accessToken: string, crsfToken: string): ILoginResponse {
        const decoded = this.jwtService.decode<IJwtPayload>(accessToken);
        const expiredAt = decoded.exp - Math.floor(Date.now() / 1000);
        return {
            accessToken: accessToken,
            expiresAt: expiredAt,
            tokenType: "Bearer",
            crsfToken: crsfToken
        };
    }
    async validateUser(
        email: string,
        password: string
    ): Promise<UserWithoutPassword | null> {
        const user = await this.prismaService.user.findUnique({
            where: { email }
        });
        if (!user) {
            return null;
        }
        const isPassworValid = await bcrypt.compare(password, user.password);
        if (!isPassworValid) {
            return null;
        }
        const { password: _, ...result } = user;
        return result;
    }
}
