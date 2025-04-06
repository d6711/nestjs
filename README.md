# config prisma

npx prisma
npx prisma init
npx prisma migrate dev --name init

# config seed

npm install -D typescript ts-node @types/node

# run the db seed

npx prisma db seed

# auth
$ npm install --save @nestjs/passport passport passport-local
$ npm install --save-dev @types/passport-local
$ npm install --save @nestjs/jwt passport-jwt
$ npm install --save-dev @types/passport-jwt

# Các gói cần thiết cho runtime
npm install @nestjs/passport passport passport-local passport-jwt @nestjs/jwt

# Các gói cần thiết cho type dev
npm install -D @types/passport-local @types/passport-jwt

