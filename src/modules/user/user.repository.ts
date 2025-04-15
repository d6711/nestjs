import { Injectable } from "@nestjs/common";
import { BaseRepository } from "src/repositories/base.repository";
import { PrismaService } from "../prisma/prisma.service";
import { User } from "@prisma/client";


@Injectable()
export class UserRepository extends BaseRepository<typeof PrismaService.prototype.user, User> {

    constructor(private readonly prisma: PrismaService) {
        super(prisma.user)
    }
    
}