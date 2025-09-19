import { Controller, Get, UseGuards } from "@nestjs/common";
import { JwtAuthGuard } from "../auth/guards/jwt-auth.guard";
import { GetUser } from "../../common/decorators/get-user.decorator";

@Controller("users")
export class UsersController {
  @Get("profile")
  @UseGuards(JwtAuthGuard)
  getProfile(@GetUser() user: any) {
    return user;
  }
}
