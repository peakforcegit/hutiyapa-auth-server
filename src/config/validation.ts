import { plainToInstance } from "class-transformer";
import { IsEnum, IsInt, Max, Min, validateSync } from "class-validator";
class EnvironmentVariables {
  @IsInt() @Min(1) @Max(65535) PORT!: number;
  @IsEnum(["development","test","production"] as any) NODE_ENV!: "development" | "test" | "production";
}
export function validate(config: Record<string, unknown>) {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, { enableImplicitConversion: true });
  const errors = validateSync(validatedConfig, { skipMissingProperties: false });
  if (errors.length > 0) { throw new Error(errors.toString()); }
  return validatedConfig;
}
