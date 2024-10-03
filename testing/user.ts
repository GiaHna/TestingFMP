import request from 'supertest'
import app from '../main'
import { databaseService } from '~/services/connectDB.service'
import { StatusCodes } from 'http-status-codes'
import { string } from 'joi'
import { mock } from 'node:test'
import { response } from 'express'

describe('User Routes', () => {
  let mockToken = ''

  beforeAll(async () => {
    await databaseService.connect()
    const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst20@gmail.com', password: '475_DienBienPhu' })
    mockToken = response.body.data.access_token
  })

  afterAll(async () => {
    await databaseService.disConnect()
  })

  describe('POST /api/v1/users/password/reset', () => {
    const mockEmail = 'phamhanst20@gmail.com' 
    const mockPassword = '475_DienBienPhu1'  
    const mockConfirmPassword = '475_DienBienPhu1';
    const mockPayload = { email: mockEmail, password: mockPassword, confirm_password: mockConfirmPassword }
    const resetPasswordRoute = '/api/v1/users/password/reset'

    it('should return 400 if the password field is empty', async () => {
      
      const emptyPasswordPayload = { 
        email: mockEmail, 
        password: '', 
        confirm_password: mockConfirmPassword 
      }
      
      const response = await request(app).post(resetPasswordRoute).set('Authorization', `Bearer ${mockToken}`).send(emptyPasswordPayload)

      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
        password: {
          type: 'field',
          value: '',
          msg: 'Password is required.',
          path: 'password',
          location: 'body'
        },
        confirm_password: {
          type: 'field',
          value: mockConfirmPassword,
          msg: 'Confirm password must match the password.',
          path: 'confirm_password',
          location: 'body'
      }
    })
  })



    it('should return 422 if Password and Confirm Password do not match', async () => {
      const mismatchedPasswordPayload = { 
        email:mockEmail, password: '475_DienBienPhu', confirm_password: '475_DienBienPh' }
      
      const response = await request(app).post(resetPasswordRoute).set('Authorization', `Bearer ${mockToken}`).send(mismatchedPasswordPayload)
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
      expect(response.body.errors).toEqual({
        confirm_password: {
          type: 'field',
          value: mismatchedPasswordPayload.confirm_password,
          msg: 'Confirm password must match the password.',
          path: 'confirm_password',
          location: 'body'
        }}
      )
   
    })
  
    it('should return 401 Unauthorized if no token is provided', async () => {
      const response = await request(app).post(resetPasswordRoute).send(mockPayload)
      expect(response.status).toBe(StatusCodes.UNAUTHORIZED)
      expect(response.body).toEqual({
        statusCode: StatusCodes.UNAUTHORIZED,
        message: 'Authentication token missing or invalid'
      })
    })

    it('should return 400 if Password reset failed due to leaving email blank', async () => {
      
      const blankEmailPayload = { email:'', password: '475_DienBienPhu',confirm_password: '475_DienBienPhu' }
      const response = await request(app).post(resetPasswordRoute).set('Authorization', `Bearer ${mockToken}`).send(blankEmailPayload)
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
        email: {
          type: 'field',
          value: '',
          msg: 'The email is required.',
          path: 'email',
          location: 'body'

        }
      })
   
    })
    it('should return 401 Unauthorized if token is invalid', async () => {
      const response = await request(app).post(resetPasswordRoute).set('Authorization', `Bearer ${mockToken}`).send(mockPayload)
      expect(response.status).toBe(401)
      expect(response.body).toEqual({
        statusCode: 401,
        message: 'Invalid or expired token'
      })
    })
    it('should return 200 and allow password reset if user is authenticated', async () => {
      const response = await request(app).post(resetPasswordRoute).set('Authorization', `Bearer ${mockToken}`).send(mockPayload)
      expect(response.status).toBe(StatusCodes.OK)
      console.log(response.body);
      expect(response.body).toEqual({
        statusCode: StatusCodes.OK,
        message: 'The password reset was successful.',
        data: '',
        dateTime: expect.any(String),
    })
  })
    it('Should return 404 if password reset failed due to invalid email', async () => {
      const invalidEmailPayload = { email: 'nonexistent@example.com', password: '475_DienBienPhu',confirm_password: '475_DienBienPhu' }

      const response = await request(app).post(resetPasswordRoute).send(invalidEmailPayload)
      expect(response.status).toBe(StatusCodes.NOT_FOUND)
      expect(response.body.errors).toEqual({
          email: {
            type: 'field',
            value: invalidEmailPayload.email,
            msg: 'The email address does not exist or removed. Please use a valid one or register.',
            path: 'email',
            location: 'body'
          }
      })
    })
  
    it('should return 500 Internal Server Error if database operation fails', async () => {
      const mockErrorMessage = 'Database error'
      const response = await request(app).post(resetPasswordRoute).set('Authorization', `Bearer ${mockToken}`).send(mockPayload)
      expect(response.status).toBe(500)
      expect(response.body).toEqual({
        statusCode: 500,
        message: mockErrorMessage
      })
    })
  })

  
  describe('POST /api/v1/users/register', () => {
    const newFullName= 'Jack Trinh'
    const newEmail= 'jack97@gmail.com'
    const newPassword= '475_DienBienPhu'
    const newConfirmPassword= '475_DienBienPhu'
    const newPhone= '0771234587'
    const mocknewUser = {   
    full_name: newFullName,email:newEmail,password: newPassword,confirm_password: newConfirmPassword,phone: newPhone} 
    const registerRoute = '/api/v1/users/register'


    it('should return 201 if successfully register a new user', async () => {
      const response = await request(app).post(registerRoute).send(mocknewUser)
      expect(response.status).toBe(StatusCodes.CREATED)
      expect(response.body).toEqual({
        statusCode: StatusCodes.CREATED,
        message: 'You have successfully created an account. Please check your email to verify your OTP.',
        data: {
          _id: expect.any(String),
          full_name: newFullName,
          email: newEmail,
          access_token: expect.any(String),
          refresh_token: expect.any(String)
        },
        dateTime: expect.any(String)
      })
    })
    

    it('should return 409 if email is already registered', async () => {
      const existingEmail = 'duongquocnam224400@gmail.com';
      const mockExistingUser = {
        full_name: 'Nguyen Van B',
        email: existingEmail,
        password: newPassword,
        confirm_password: newConfirmPassword,
        phone: '0776533354',
      };

      const response = await request(app).post(registerRoute).send(mockExistingUser);
      expect(response.status).toBe(StatusCodes.CONFLICT);
      expect(response.body.errors).toEqual({
        email: {
          type: 'field',
          value: existingEmail,
          msg: 'Email already in use. Please use another email.',
          path: 'email',
          location: 'body',
        }
      })
    })
    it('should return 422 if email format is invalid', async () => {
      
      const invalidEmail = 'phamhan000@gmail'
      const invalidUser = {
        full_name: 'Nguyen Van c',
        email: invalidEmail,
        password: newPassword,
        confirm_password: newConfirmPassword,
        phone: '0776531154',
      };

      const response = await request(app).post(registerRoute).send(invalidUser)

      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
      expect(response.body.errors).toEqual({
          email: {
            type: 'field',
            value: invalidEmail,
            msg: 'Email must end with @gmail.com or @gmail.edu.com.',
            path: 'email',
            location: 'body'
          }
      })
      })

      
      it('should return 400 if fullname have special characters', async () => {
        
        const invalidFullnameUser = {
          full_name:'pham hanst@@!', // Fullname with special characters or too short
          email: 'testuser@gmail.com',
          password: 'Password@123',
          confirm_password: 'Password@123',
          phone: '0773416789'
        };
      
        const response = await request(app).post(registerRoute).send(invalidFullnameUser);
        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
           full_name: {
            type: "field",
            value: invalidFullnameUser.full_name,
            msg: 'Invalid full name format.',
            path: 'full_name',
            location: 'body'
         }
      })
      })
      it('should return 400 if password does not meet requirements', async () => {
        const weakPassword ='pass'
        const weakPasswordUser = {
          full_name: 'Test Userr',
          email: 'testuser@gmail.com',
          password: weakPassword, // password too short and no special character
          confirm_password: weakPassword,
          phone: '0773413789'
        };
      
        const response = await request(app).post(registerRoute).send(weakPasswordUser);
        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
          confirm_password: {
            type: 'field',
            value: weakPassword,
            msg: 'Incorrect confirm password format.',
            path: 'confirm_password',
            location: 'body'
          },         
          password: {
              type: 'field',
              value: weakPassword,
              msg: 'Password must be at least 8 characters long and contain at least one special character.',
              path: 'password',
              location: 'body'
            }
          })
        })
      })
    
  

  describe('POST /api/v1/users/login', () => {
    const mockEmail = 'duongquocnam224400@gmail.com'
    const mockPassword = 'Admin@1234'
    const mockPayload = { email: mockEmail, password: mockPassword }
    const validEmail = 'testuser@example.com'
    const validPassword = 'TestPassword123'
    const loginRoute = '/api/v1/users/login'
    // Test case for successful login
    it('should return 200 and login successfully with access and refresh tokens', async () => {
      const response = await request(app).post(loginRoute).send(mockPayload)
      expect(response.status).toBe(StatusCodes.OK)
      expect(response.body).toEqual({
        statusCode: 200,
        message: 'Login successfully.',
        data: {
          _id: expect.any(String),
          email: mockEmail,
          access_token: expect.any(String),
          refresh_token: expect.any(String)
        },
        dateTime: expect.any(String)
      })
    })
    it('should return 400 Bad Request if Email is not registered', async () => {
      const unregisteredEmail = 'phamhan1@gmail.com'
      const response = await request(app).post(loginRoute).send({ email: unregisteredEmail, password: '475_DienBienPhu' })
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
          email: {
          type: 'field',
          value: unregisteredEmail,
          msg: 'The email does not exist or has been removed. Please provide a valid email or register.',
          path: 'email',
          location: 'body'
        }
    })
})
    
  it('should return 400 Bad Request if email format is invalid', async () => {
    const invalidEmail = 'giahanstgmail.com'
    const response = await request(app).post(loginRoute).send({ email: invalidEmail, password: '475_DienBienPhu' })

    expect(response.status).toBe(StatusCodes.BAD_REQUEST)
    expect(response.body.errors).toEqual({
        email: {
            type: 'field',
            value: invalidEmail,
            msg: 'Invalid email address.',
            path: 'email',
            location: 'body'
        }
  })
  })

    it('should return 400 validation error if email and password are left blank', async () => {
      const response = await request(app).post(loginRoute).send({ email: '', password: '' })
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
          email: {
            type: 'field',
            value: '',
            msg: 'Email is required.',
            path: 'email',
            location: 'body'
          },
          password: {
            type: 'field',
            value: '',
            msg: 'Password is required.',
            path: 'password',
            location: 'body'
          }
        
      })
    })

    it('should return 400 Bad Request if password is left blank', async () => {
      const response = await request(app).post(loginRoute).send({ email: mockEmail, password: '' })
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
              password: {
                  type: 'field',
                  value: '',
                  msg: 'Password is required.',
                  path: 'password',
                  location: 'body'
              }
      })
    })
    it('should return 400 Bad Request if email is left blank', async () => {
      const response = await request(app).post(loginRoute).send({ email: '', password: '475_DienBienPhu' })
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
              email: {
                  type: 'field',
                  value: '',
                  msg: 'Email is required.',
                  path: 'email',
                  location: 'body'
              }
      })
    })

    it('should return 401 Bad Request if email is correct but password is wrong', async () => {
      const correctEmail = 'duongquocnam224400@gmail.com'
      const wrongPassword = 'WrongPassword123'
      const response = await request(app).post(loginRoute).send({ 
        email: correctEmail, 
        password: wrongPassword 
      })
      
      expect(response.status).toBe(StatusCodes.UNAUTHORIZED)
      expect(response.body.errors).toEqual({
          password: {
            type: 'field',
            value: wrongPassword,
            msg: 'Incorrect email or password.',
            path: 'password',
            location: 'body'
          }
        
      })
    })
    it('should lock the account after 5 failed login attempts', async () => {
      const maxAttempts = 5
      const incorrectPassword = '475DienBienPhu'
      const correctEmail = 'duongquocnam224400@gmail.com'
    
      // Loop to simulate multiple failed login attempts
      for (let i = 0; i < maxAttempts; i++) {
        const response = await request(app).post('/api/v1/users/login').send({
          email: correctEmail,
          password: incorrectPassword
        })
        
        // Check that each attempt fails with incorrect password
        expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
        expect(response.body).toEqual({
      
              message: 'Incorrect email or password.',
              created_at: expect.any(String),
              updated_at: expect.any(String),
              messageConstants: null,
              name: "ErrorWithStatus"
})
          
        }
      
    
      // On the 6th attempt, the account should be locked
      const lockedResponse = await request(app).post('/api/v1/users/login').send({
        email: correctEmail,
        password: incorrectPassword
      })
      
      expect(lockedResponse.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY) // Assuming 403 for locked account
      expect(lockedResponse.body.errors).toEqual({
        email: {
          type: 'field',
          msg: 'The account has been blocked.',
          path: 'email',
          location: 'body'
        }
      })
    })
        it('should return 403 Forbidden if the account is not verified', async () => {
      const unverifiedEmail = 'phamhanst1@gmail.com'
      const unverifiedPassword = '475_DienBienPhu'
      const response = await request(app).post(loginRoute).send({ 
        email: unverifiedEmail, 
        password: unverifiedPassword 
      })
      
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
      expect(response.body.errors).toEqual({
       email: {
          type: 'field',
          value: unverifiedEmail,
          msg: 'Account is unverified.',
          path: 'email',
          location: 'body'
             }
          })
      })
  })

  // Test case for profile retrieval
  describe('GET /api/v1/users/profile', () => {
    let accessToken= ''
    const profileRoute = '/api/v1/users/@me/profile'
    const profileEmail = 'phamhanst4@gmail.com'
    const profilePassword = '475_DienBienPhu'
 
    // Test case for successful profile retrieval
    it('should return 200 and the user profile when a valid token is provided', async () => {
      const response = await request(app).get(profileRoute).set('Authorization', `Bearer ${mockToken}`);
      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body).toEqual({
        statusCode: 200,
        message: 'The user account information was successfully retrieved.',
        data: {
            _id: expect.any(String),
            full_name: 'dádasd',
            email: 'phamhanst20@gmail.com',
            phone: '0915222222',
            role: 'Admin',
            gender: 'Female',
            failedLoginAttempts: 0,
            address: '475_DienBienPhu',
            avatar: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1720197825/avatar/iwdsqojke1mxj0bla6r2.jpg',
            thumbnail: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1720198873/c8mpg9zqr5rgux54pght.jpg',
            isOnline: false,
            isBlocked: false,
            lastFailedLoginAttempt: null,
            _destroy: false,
            password_change_at: expect.any(String),
            created_at: expect.any(String),
            updated_at: expect.any(String)
          },
          dateTime: expect.any(String)
        });
    });
  
    // Test case for unauthorized access due to missing token
    it('should return 401 Unauthorized if no token is provided', async () => {
      const response = await request(app).get(profileRoute);
      
      expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(response.body).toEqual({       
           message: 'You must be logged in to continue.',
           created_at: expect.any(String),
           updated_at: expect.any(String),
           messageConstants: null,
           name: "ErrorWithStatus"
        })
    });
  
    // Test case for unauthorized access due to an invalid token
    it('should return 401 Unauthorized if an invalid token is provided', async () => {
      const response = await request(app).get(profileRoute).set('Authorization', 'Bearer 5yJCCcg026Jg4AYt2LU17z1XQDCK1vetYLxsARdpKjt3RBb9ODhE5a9LKvfjByWi');
      expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(response.body).toEqual({
            message: 'jwt malformed',
            created_at: expect.any(String),
            updated_at: expect.any(String),
            messageConstants: null,
            name: "ErrorWithStatus"
        });
    });
  });

  //Test case for forgot-password
    describe('POST /api/v1/users/password/forgot', () => {
    const forgotPasswordRoute = '/api/v1/users/password/forgot'
    const forgotEmail = 'jack97@gmail.com'
    const mockEmail = 'phamhanst20@gmail.com'  
    
   //return 200 if request is successful
    it('should return 200 and send a password reset email when a valid registered email is provided', async () => {
      const response = await request(app).post(forgotPasswordRoute).send({ email: mockEmail });
      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body).toEqual({
        statusCode: StatusCodes.OK,
        message: 'The request to reset the password has been successfully processed.',
        data:'',
        dateTime: expect.any(String)
        })
     })

    //return 404 Not Found if the email has been deleted 
    it('should return 404 Not Found if the email has been deleted', async () => {
      const response = await request(app).post(forgotPasswordRoute).send({ email:forgotEmail });  
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
      expect(response.body.errors).toEqual({
        email: {
            type: 'field',
            value: forgotEmail,
            msg: 'The email does not exist or has been removed. Please provide a valid email or register.',
            path: 'email',
            location:'body'
                    }
            })
       })

     //return 404 Not Found if the email does not exist  
      it('should return 404 Not Found if the email does not exist', async () => {
      const response = await request(app).post(forgotPasswordRoute).send({ email:'phamhanst@gmail.com' });  
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
      expect(response.body.errors).toEqual({
        email: {
            type: 'field',
            value: 'phamhanst@gmail.com',
            msg: 'The email does not exist or has been removed. Please provide a valid email or register.',
            path: 'email',
            location:'body'
                    }
              })
          })
       
      //return 400 Bad Request if the email format is invalid
      it('should return 400 Bad Request if the email format is invalid', async () => {
      const invalidEmail = 'phamhanstgmail'
      const response = await request(app).post(forgotPasswordRoute).send({ email:invalidEmail});
      expect(response.status).toBe(StatusCodes.BAD_REQUEST);
      expect(response.body.errors).toEqual({
          email: {
          type: 'field',
          value: invalidEmail,
          msg: 'Please provide a valid email address.',
          path: 'email',
          location: 'body'
                  }
               }) 
            })

      //return 400 if email field is blank
      it('should return 400 Bad Request if email field is blank', async () => {
        const response = await request(app).post(forgotPasswordRoute).send({ email: '' });
        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
        email: {
          type: 'field',
          value: '',
          msg: 'Email is required.',
          path: 'email',
          location: 'body'
            }
         })             
      })
    })

    //test case for user/password-change
      describe('POST /api/v1/users/password/change', () => {
        let accessToken = ''
        let newToken=''
        const changePasswordRoute = '/api/v1/users/password/change'
        const changeOldPassword = '475_DienBienPhu1'        //*Dien lai mat khau moi lan test
        const changeNewPassword = '475_DienBienPhu'        //*
        const changeConfirmPassword = '475_DienBienPhu'   //*
        const samePassword = '475_DienBienPhu'   //cai nay khong can dien lai
        const changePayload = {old_password: changeOldPassword,password: changeNewPassword,confirm_password: changeConfirmPassword}
      
      beforeAll(async () => {
          const response = await request(app).post('/api/v1/users/login').send({ email: 'testuser@gmail.com', password: '475_DienBienPhu1' })
          accessToken = response.body.data.access_token
        })//login first to get access token
         
      beforeAll(async () => {
          const response = await request(app).post('/api/v1/users/login').send({ email: 'testuser1@gmail.com', password: samePassword })
          newToken = response.body.data.access_token
        })//login first to get access token 
      

       //return 200 if password changed successully 
        it('should return 200 if password changed successfully', async () => {  
        const response = await request(app).post(changePasswordRoute).set('Authorization', `Bearer ${accessToken}`).send(changePayload)
        expect(response.status).toBe(StatusCodes.OK)  // Check for 200 OK status
        expect(response.body).toEqual({
          statusCode: StatusCodes.OK,
          message: 'Your password has been successfully changed.',
          data: '',
          dateTime: expect.any(String)
           })
        })
       
       //reuturn 400 if old password is invalid
        it('should return 400 Bad Request if old password is invalid', async () => {
        const invalidOldPassword = '475_DienBienPhu2'
        const changePayload = {old_password: invalidOldPassword,password: changeNewPassword,confirm_password: changeConfirmPassword}
        const response = (await request(app).post(changePasswordRoute).set('Authorization', `Bearer ${accessToken}`).send(changePayload))
        expect(response.status).toBe(StatusCodes.BAD_REQUEST)
        expect(response.body.errors).toEqual({
          old_password: {
              type: 'field',
              value: invalidOldPassword,
              msg: 'Old password is incorrect.',
              path: 'old_password',
              location: 'body'
                }
            })          
        })

      //return 400 if new password and confirm password do not match  
      it('should return 400 Bad Request if new password and confirm password do not match', async () => {
        const invalidConfirmPassword = '475_DienBienPhu3'
        const changePayload = {old_password: changeOldPassword,password: changeNewPassword,confirm_password: invalidConfirmPassword} 
        const response = await request(app).post(changePasswordRoute).set('Authorization', `Bearer ${accessToken}`).send(changePayload) 
        expect(response.status).toBe(StatusCodes.BAD_REQUEST)
        expect(response.body.errors).toEqual({
          confirm_password: {
            type: 'field',
            value: invalidConfirmPassword,
            msg: 'Confirm password must match the password.',
            path: 'confirm_password',
            location: 'body'
                  },
           old_password: {
           type: 'field',
           value: changeOldPassword,
           msg: 'Old password is incorrect.',
           path: 'old_password',
           location: 'body'       
              }
            })
        })

        //return 422 if new password does not meet the strength requirements
        it('should return 422 unprocessable if new password does not meet the strength requirements', async () => {
          const weakNewPassword = 'dienbienphu'
          const changePayload = {old_password: changeOldPassword,password: weakNewPassword,confirm_password: weakNewPassword} 
          const response = await request(app).post(changePasswordRoute).set('Authorization', `Bearer ${accessToken}`).send(changePayload) 
          expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
          expect(response.body.errors).toEqual({
              password: {
              type: 'field',
              value: weakNewPassword,
              msg: 'Password must meet the strength requirements: 8-16 characters, with at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol.',
              path: 'password',
              location: 'body'
            },
            confirm_password: {
              type: 'field',
              value: weakNewPassword,
              msg: 'Confirm password must be a string.',
              path: 'confirm_password',
              location: 'body'
                    },
             old_password: {
             type: 'field',
             value: changeOldPassword,
             msg: 'Old password is incorrect.',
             path: 'old_password',
             location: 'body'       
                }
              })
          })
         
        //return 422 if new password match the old password
        it('should return 422 unprocessable if new password match the old password', async () => {
        const changePayload = {old_password: samePassword,password: samePassword,confirm_password: '475_DienBienPhu'}    
        const response = await request(app).post(changePasswordRoute).set('Authorization', `Bearer ${newToken}`).send(changePayload)
        expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
        expect(response.body.errors).toEqual({
          password: {
            type: 'field',
            value: samePassword,
            msg: "New password cannot be the same as the old password.",
            path: "password",
            location: "body"
                 } 
             }) 
          })

        //should return 400 if old password field is blank
        it('should return 400 Bad Request if old password field is blank', async () => {
          const changePayload = {old_password: '',password: changeNewPassword,confirm_password: changeConfirmPassword}
          const response = await request(app).post(changePasswordRoute).set('Authorization', `Bearer ${accessToken}`).send(changePayload)
          expect(response.status).toBe(StatusCodes.BAD_REQUEST)
          expect(response.body.errors).toEqual({
            old_password: {
              type: 'field',
              value: '',
              msg: 'Old password is required.',
              path: 'old_password',
              location: 'body'
            }
          })

        })  
        })              
    // Test case for account locked or disabled
    // it('should return 403 Forbidden if the account is locked', async () => {
    //   const mockErrorMessage = 'Account is locked'
    //   const response = await request(app).post(loginRoute).send({ email: mockEmail, password: mockPassword })
    //   expect(response.status).toBe(StatusCodes.FORBIDDEN)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.FORBIDDEN,
    //     message: mockErrorMessage
    //   })
    // })

    // Test case for too many login attempts
    // it('should return 429 Too Many Requests if too many login attempts', async () => {
    //   const response = await request(app).post(loginRoute).send({ email: mockEmail, password: 'WrongPassword123' })
    //   expect(response.status).toBe(StatusCodes.TOO_MANY_REQUESTS)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.TOO_MANY_REQUESTS,
    //     message: 'Too many login attempts. Please try again later.'
    //   })
    // })

    // Test case for invalid credentials
    // it('should return 401 Unauthorized for invalid credentials', async () => {
    //   const response = await request(app).post(loginRoute).send({ email: 'wronguser@example.com', password: 'WrongPassword123' })

    //   expect(response.status).toBe(StatusCodes.UNAUTHORIZED)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.UNAUTHORIZED,
    //     message: 'Invalid email or password'
    //   })
    // })

    // Test case for too short password
    // it('should return 400 Bad Request if password is too short', async () => {
    //   const response = await request(app).post(loginRoute).send({ email: mockEmail, password: '123' }) // Too short password
    //   expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.UNPROCESSABLE_ENTITY,
    //     message: 'Password must be at least 6 characters'
    //   })
    // })

    // Test case for invalid email format
    // it('should return 400 Bad Request if email format is invalid', async () => {
    //   const response = await request(app).post(loginRoute).send({ email: 'invalidEmail', password: mockPassword })
    //   expect(response.status).toBe(StatusCodes.BAD_REQUEST)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.BAD_REQUEST,
    //     message: 'Invalid email format'
    //   })
    // })

    // Test case for missing email
    // it('should return 400 Bad Request if email is missing', async () => {
    //   const response = await request(app).post('/api/v1/users/login').send({ password: mockPassword }) // Missing email

    //   expect(response.status).toBe(StatusCodes.BAD_REQUEST)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.BAD_REQUEST,
    //     message: 'Email and password are required'
    //   })
    // })

    // Test case for missing password
    // it('should return 400 Bad Request if password is missing', async () => {
    //   const response = await request(app).post('/api/v1/users/login').send({ email: mockEmail }) // Missing password

    //   expect(response.status).toBe(StatusCodes.BAD_REQUEST)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.BAD_REQUEST,
    //     message: 'Email and password are required'
    //   })
    // })

    // Test case for database connection issues
    // it('should return 500 Internal Server Error if there is a database error', async () => {
    //   const mockErrorMessage = 'Internal server error. Please try again later.'
    //   const response = await request(app).post(loginRoute).send({ email: validEmail, password: validPassword })
    //   expect(response.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.INTERNAL_SERVER_ERROR,
    //     message: mockErrorMessage
    //   })
    // })

    // Test case for invalid JSON payload
    // it('should return 400 Bad Request if the request payload is invalid', async () => {
    //   const response = await request(app).post(loginRoute).set('Content-Type', 'application/json').send('invalid JSON payload')
    //   expect(response.status).toBe(StatusCodes.BAD_REQUEST)
    //   expect(response.body).toEqual({
    //     statusCode: StatusCodes.BAD_REQUEST,
    //     message: 'Malformed JSON request'
    //   })
    // })

  })