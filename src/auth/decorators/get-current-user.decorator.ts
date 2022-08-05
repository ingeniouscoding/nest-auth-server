import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const GetCurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return data
      ? request.user?.[data]
      : request.user;
  });
