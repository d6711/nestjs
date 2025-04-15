import { Injectable } from "@nestjs/common";

type PrismaModel<TModel> = {
    findUnique(args: unknown): Promise<TModel | null>,
    findMany(args?: unknown): Promise<TModel[]>,
    create(args: unknown): Promise<TModel>,
    update(args: unknown): Promise<TModel>,
    delete(args: unknown): Promise<TModel>
}

@Injectable()
export class BaseRepository<T extends PrismaModel<TModel>, TModel, ID = number> {

    constructor(protected readonly model: T) { }

    async findById(id: ID): Promise<TModel | null> {
        return await this.model.findUnique({ where: { id } })
    }
}
