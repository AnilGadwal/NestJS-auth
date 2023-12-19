import { IsNotEmpty } from "class-validator";

export class SignupDto {
    @IsNotEmpty()
    public name: string

    @IsNotEmpty()
    public email: string;

    @IsNotEmpty()
    public password: string;
}

export class SigninDtop {
    @IsNotEmpty()
    public email: string;

    @IsNotEmpty()
    public password: string;
}