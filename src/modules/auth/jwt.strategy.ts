import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { PrismaService } from "../prisma/prisma.service";
import { jwtConstants } from "./auth.constants";
import { IJwtPayload } from "./auth.interface";


@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly prismaService: PrismaService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: jwtConstants.secret
        })
    }
    validate(payload: IJwtPayload) {
        const user = this.prismaService.user.findUnique({
            where: { id: parseInt(payload.sub) }
        })
        if (!user) {
            
        }
        return { userId: payload.sub, guard: payload.guard }
    }
}