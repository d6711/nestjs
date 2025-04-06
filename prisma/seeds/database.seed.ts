import { PrismaClient } from "@prisma/client";
import * as bcrypt from "bcrypt";

const prisma = new PrismaClient();
async function main() {
    const saltOrRounds = 10;
    const user = await prisma.user.create({
        data: {
            email: "dev.lequang176@gmail.com",
            password: await bcrypt.hash("password", saltOrRounds),
            name: "dev"
        }
    });

    console.log({ user });
}
main()
    .then(async () => {
        await prisma.$disconnect();
    })
    .catch(async (e) => {
        console.error(e);
        await prisma.$disconnect();
        process.exit(1);
    });
