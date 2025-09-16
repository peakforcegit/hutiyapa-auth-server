import { ArgumentMetadata, BadRequestException, Injectable, PipeTransform } from "@nestjs/common";
import { plainToInstance } from "class-transformer";
import { validate } from "class-validator";
@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    if (!metatype || (metatype as any) === String || (metatype as any) === Boolean || (metatype as any) === Number || (metatype as any) === Array || (metatype as any) === Object) {
      return value;
    }
    const object = plainToInstance(metatype, value);
    const errors = await validate(object, { whitelist: true, forbidNonWhitelisted: true });
    if (errors.length > 0) {
      throw new BadRequestException(errors);
    }
    return value;
  }
}
