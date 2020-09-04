import { Resolver, Mutation, InputType, Field, Ctx, Arg, ObjectType } from "type-graphql";
import { MyContext } from "src/types";
import { User } from "../entities/User";
import argon2 from 'argon2';

@InputType()
class UsernamePasswordInput{
    @Field()
    username: string

    @Field()
    password: string
}

@ObjectType()
class FieldError{
    @Field()
    field: string;

    @Field()
    message: string;
}

@ObjectType() //you return objectType(eg. Mutations etc) and you put InputType as args
class UserResponse{

    @Field(() => [FieldError], {nullable: true})
    errors?: FieldError[];

    @Field(() => User, {nullable: true})
    user?: User;
}

@Resolver()
export class UserResolver{
    @Mutation(() => UserResponse)
    async register(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() {em}:MyContext
    ):Promise<UserResponse>{

        if(options.username.length <= 2){
            return{
                errors:[{
                field: 'username',
                message: 'length must be greater than 2'
                },
            ],
            };
        }

        if(options.password.length <= 3){
            return{
                errors:[{
                field: 'password',
                message: 'length must be greater than 3'
                },
            ],
            };
        }

        const hashedPassword = await argon2.hash(options.password);
        const user = em.create(User, {username: options.username, password: hashedPassword})
        try{
            await em.persistAndFlush(user);
        } catch(err){
            //duplicate username error
            if(err.code === '23505' || err.detail.includes("already exist")){
                return{
                    errors:[{
                        field: "username",
                        message: "username already taken",
                    }]
                }
            }
            console.log("message:", err.message);
        }
        
        return {user};
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() {em}:MyContext
    ):Promise<UserResponse>{
        const user = await em.findOne(User, {username: options.username});
        if(!user){
            return {
                errors: [{
                    field: 'username',
                    message: "Username doesn't exist"
                },
            ]
            };
        }
        const valid = await argon2.verify(user.password, options.password);
        if(!valid){
            return {
                errors: [{
                    field: 'password',
                    message: "Incorrect Password",
                },
            ]
            };
        }
        return {
            user,
        };
        
    }
}