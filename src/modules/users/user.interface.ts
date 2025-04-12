export interface User {
  id: bigint;
  name: string;
  email: string;
  password: string;
  phone?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type UserWithoutPassword = Omit<User, "password">;
