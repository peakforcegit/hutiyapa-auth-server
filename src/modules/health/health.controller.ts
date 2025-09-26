import { Controller, Get } from "@nestjs/common";
import { ResetPasswordDto } from '../auth/dtos/reset-password.dto';

@Controller("health")
export class HealthController { 
  @Get() 
  check() { 
    return { status: "ok" }; 
  } 
}
