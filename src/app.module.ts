import { Module } from "@nestjs/common";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { AuthModule } from "./modules/auth/auth.module";
import { CacheModule } from "@nestjs/cache-manager";
import { createKeyv } from "@keyv/redis";
import { Keyv } from "keyv";
import { CacheableMemory } from "cacheable";

@Module({
  imports: [
    AuthModule,
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: async () => {
        return {
          stores: [
            new Keyv({
              store: new CacheableMemory({ ttl: 60000, lruSize: 5000 }),
              namespace: "nestjs-memory-cache"
            }),
            createKeyv("redis://localhost:6379/1", {
              namespace: "nestjs-newbie"
            })
          ]
        };
      }
    })
  ],
  controllers: [AppController],
  providers: [AppService]
})
export class AppModule {}
