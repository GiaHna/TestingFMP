import request from 'supertest'
import app from '../main'
import { databaseService } from '~/services/connectDB.service'
import { StatusCodes } from 'http-status-codes'
import { string } from 'joi'
import { mock } from 'node:test'
import { response } from 'express'
import { create, get } from 'lodash'
import { access } from 'node:fs'

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
    const mockConfirmPassword = '475_DienBienPhu1'
    const mockPayload = { email: mockEmail, passord: mockPassword, confirm_password: mockConfirmPassword }
    const resetPasswordRoute = '/api/v1/users/password/reset'

    it('should return 400 if the password field is empty', async () => {
      const emptyPasswordPayload = {
        email: mockEmail,
        password: '',
        confirm_password: mockConfirmPassword
      }

      const response = await request(app)
        .post(resetPasswordRoute)
        .set('Authorization', `Bearer ${mockToken}`)
        .send(emptyPasswordPayload)

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
        email: mockEmail,
        password: '475_DienBienPhu',
        confirm_password: '475_DienBienPh'
      }

      const response = await request(app)
        .post(resetPasswordRoute)
        .set('Authorization', `Bearer ${mockToken}`)
        .send(mismatchedPasswordPayload)
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY)
      expect(response.body.errors).toEqual({
        confirm_password: {
          type: 'field',
          value: mismatchedPasswordPayload.confirm_password,
          msg: 'Confirm password must match the password.',
          path: 'confirm_password',
          location: 'body'
        }
      })
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
      const blankEmailPayload = { email: '', password: '475_DienBienPhu', confirm_password: '475_DienBienPhu' }
      const response = await request(app)
        .post(resetPasswordRoute)
        .set('Authorization', `Bearer ${mockToken}`)
        .send(blankEmailPayload)
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
      const response = await request(app)
        .post(resetPasswordRoute)
        .set('Authorization', `Bearer ${mockToken}`)
        .send(mockPayload)
      expect(response.status).toBe(401)
      expect(response.body).toEqual({
        statusCode: 401,
        message: 'Invalid or expired token'
      })
    })
    it('should return 200 and allow password reset if user is authenticated', async () => {
      const response = await request(app)
        .post(resetPasswordRoute)
        .set('Authorization', `Bearer ${mockToken}`)
        .send(mockPayload)
      expect(response.status).toBe(StatusCodes.OK)
      console.log(response.body)
      expect(response.body).toEqual({
        statusCode: StatusCodes.OK,
        message: 'The password reset was successful.',
        data: '',
        dateTime: expect.any(String)
      })
    })
    it('Should return 404 if password reset failed due to invalid email', async () => {
      const invalidEmailPayload = {
        email: 'nonexistent@example.com',
        password: '475_DienBienPhu',
        confirm_password: '475_DienBienPhu'
      }

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
      const response = await request(app)
        .post(resetPasswordRoute)
        .set('Authorization', `Bearer ${mockToken}`)
        .send(mockPayload)
      expect(response.status).toBe(500)
      expect(response.body).toEqual({
        statusCode: 500,
        message: mockErrorMessage
      })
    })
  })

  describe('POST /api/v1/users/register', () => {
    const newFullName = 'Jack Trinh'
    const newEmail = 'jack97@gmail.com'
    const newPassword = '475_DienBienPhu'
    const newConfirmPassword = '475_DienBienPhu'
    const newPhone = '0771234587'
    const mocknewUser = {
      full_name: newFullName,
      email: newEmail,
      password: newPassword,
      confirm_password: newConfirmPassword,
      phone: newPhone
    }
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
      const existingEmail = 'duongquocnam224400@gmail.com'
      const mockExistingUser = {
        full_name: 'Nguyen Van B',
        email: existingEmail,
        password: newPassword,
        confirm_password: newConfirmPassword,
        phone: '0776533354'
      }

      const response = await request(app).post(registerRoute).send(mockExistingUser)
      expect(response.status).toBe(StatusCodes.CONFLICT)
      expect(response.body.errors).toEqual({
        email: {
          type: 'field',
          value: existingEmail,
          msg: 'Email already in use. Please use another email.',
          path: 'email',
          location: 'body'
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
        phone: '0776531154'
      }

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
        full_name: 'pham hanst@@!', // Fullname with special characters or too short
        email: 'testuser@gmail.com',
        password: 'Password@123',
        confirm_password: 'Password@123',
        phone: '0773416789'
      }

      const response = await request(app).post(registerRoute).send(invalidFullnameUser)
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
      expect(response.body.errors).toEqual({
        full_name: {
          type: 'field',
          value: invalidFullnameUser.full_name,
          msg: 'Invalid full name format.',
          path: 'full_name',
          location: 'body'
        }
      })
    })
    it('should return 400 if password does not meet requirements', async () => {
      const weakPassword = 'pass'
      const weakPasswordUser = {
        full_name: 'Test Userr',
        email: 'testuser@gmail.com',
        password: weakPassword, // password too short and no special character
        confirm_password: weakPassword,
        phone: '0773413789'
      }

      const response = await request(app).post(registerRoute).send(weakPasswordUser)
      expect(response.status).toBe(StatusCodes.BAD_REQUEST)
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
      const response = await request(app)
        .post(loginRoute)
        .send({ email: unregisteredEmail, password: '475_DienBienPhu' })
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
          name: 'ErrorWithStatus'
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
  
  //PUT users/@me/profile
  describe('PUT /api/v1/users/@me/profile', () => {
    const updateProfileRoute = '/api/v1/users/@me/profile'
    const updatePayload = {full_name: 'Han Pham',phone:'0774211455',gender:'Female',avatar:'aaaaaassssss.png',thumbnail: 'aaaaaassss.png',address: 'đậhsdjkasjkdhajksdhjksadhjknn'}
    //test case for 200 if profile update successfully
    it('should return 200 OK if profile updated successfully', async () => {
      const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(updatePayload);
      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body).toEqual({
        statusCode: StatusCodes.OK,
        message: 'Your profile has been successfully updated.',
        data: '',
        dateTime: expect.any(String),
      })
    })
    // Test case for 422 when all fields are left blank
     it('should return 422 Bad Request if all fields are blank', async () => {
      const blankPayload = {
        full_name: '',
        phone: '',
        gender: '',
        avatar: '',
        thumbnail: '',
        address: ''};
      const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(blankPayload);
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY); // Or any other status your API returns for invalid inputs
      expect(response.body.errors).toEqual({
         phone: {
         type: 'field',
         value: '',
         msg: 'Phone number is required.',
         path: 'phone',
         location: 'body'
       },
         full_name: {
         type: 'field',
         value: '',
         msg: 'Full name is required.',
         path: 'full_name',
         location: 'body'
        }
    })
})
    // Test case for 401 unauthorized accesss (no provided token)
        it('should return 401 Unauthorized if the user is not authorized', async () => {
       
          const response = await request(app).put(updateProfileRoute).send(updatePayload); // No Authorization header provided
          expect(response.status).toBe(StatusCodes.UNAUTHORIZED); // Expect 401 Unauthorized
          expect(response.body).toEqual({
            message: 'You must be logged in to continue.',
            created_at: expect.any(String),
            updated_at: expect.any(String),
            messageConstants: null,
            name: 'ErrorWithStatus'
          })
        })
   // Test case for 422 Invalid phone number
        it('should return 422 Unprocessable Entity if the phone number is invalid', async () => {
          const invalidPhonePayload = {
            full_name: 'Han Pham',
            phone: 'nnnmnmnmjjj',  // Invalid phone number
            gender: 'Female',
            avatar: 'newavater.png',
            thumbnail: 'newavatar.png',
            address: 'New Address sshjkhhhhhjh jhjhjhkhjkhjk'
          };
          const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidPhonePayload);
          expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);  // Expect 422 Unprocessable Entity
          expect(response.body.errors).toEqual({
            phone: {
            type:'field',
            value: 'nnnmnmnmjjj',
            msg: 'Invalid phone number. Please provide a valid Vietnamese phone number.',
            path: 'phone',
            location: 'body'
                   }            
              })
         })
        // Test case for 422 Invalid gender value
        it('should return 422 Unprocessable Entity if the gender value is invalid', async () => {
                const invalidGenderPayload = {
                  full_name: 'Han Pham',
                  phone: '0771234568',
                  gender: 'Femaless',
                  avatar: 'string.png',
                  thumbnail: 'string.png',
                  address: 'đậhsdjkasjkdhajksdhjksadhjknn'
                };
                const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidGenderPayload);
                expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);  // Expect 422 Unprocessable Entity
                expect(response.body.errors).toEqual({
                  gender: {
                    type: 'field',
                    value: 'Femaless',
                    msg: 'Invalid gender. Please specify Male, Female, Other, etc.',
                    path: 'gender',
                    location: 'body'
                  }
                })
              })
       // Test case for 422 Invalid avatar URL
            it('should return 422 Unprocessable Entity if the avatar URL is invalid', async () => {
              const invalidAvatarPayload = {
                full_name: 'Han Pham',
                phone: '0771234568',
                gender: 'Female',
                avatar: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1720190965/photo/ieodrkuw8icv0uru2l60',
                thumbnail: 'string.png',
                address: 'đậhsdjkasjkdhajksdhjksadhjknn'
              };
              const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidAvatarPayload); 
              expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);  // Expect 422 Unprocessable Entity
              expect(response.body.errors).toEqual({
                avatar: {
                  type: 'field',
                  value: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1720190965/photo/ieodrkuw8icv0uru2l60',
                  msg: 'Avatar URL must end with .jpg, .png, .jpeg, or .gif.',
                  path: 'avatar',
                  location: 'body'
                }
              })
            })
            // Test case for 422 Invalid address
            it('should return 422 Unprocessable Entity if the address is invalid', async () => {
              const invalidAddressPayload = {
                full_name: 'Han Pham',
                phone: '0771234568',
                gender: 'Female',
                avatar: 'string.png',
                thumbnail: 'string.png',
                address: '@@@' //invalid address
              };
              const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidAddressPayload);
              expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);  // Expect 422 Unprocessable Entity
              expect(response.body.errors).toEqual({
                address: {
                  type: 'field',
                  value: '@@@',
                  msg: 'Address length must be between 10 and 200 characters.',
                  path: 'address',
                  location: 'body'
                }
              })
            })
           // Test case for 422 Blank address field
          it('should return 422 Unprocessable Entity if the address field is blank', async () => {
            const blankAddressPayload = {
              full_name: 'New User Name',
              phone: '0774567890',
              gender: 'Male',
              avatar: 'newavatar.png',
              thumbnail: 'newthumbnail.png',
              address: '',  // Blank address field
            };
            const response = await request(app).put(updateProfileRoute).set('Authorization', `Bearer ${mockToken}`).send(blankAddressPayload);
            expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);  // Expect 422 Unprocessable Entity
            expect(response.body.errors).toEqual({
              address: {
                type: 'field',
                value: '',
                msg: 'Address is required.',
                path: 'address',
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
          const changeOldPassword = '475_DienBienPhu'        //*Dien lai mat khau moi lan test
          const changeNewPassword = '475_DienBienPhu1'        //*
          const changeConfirmPassword = '475_DienBienPhu1'   //*
          const samePassword = '475_DienBienPhu'   //cai nay khong can dien lai
          const changePayload = {old_password: changeOldPassword,password: changeNewPassword,confirm_password: changeConfirmPassword}
        
        beforeAll(async () => {
            const response = await request(app).post('/api/v1/users/login').send({ email: 'testuser@gmail.com', password: '475_DienBienPhu' })
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
  //test case for forgot password

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
  //test case for get profile   
  describe('GET /api/v1/users/profile', () => {
          let  accessToken= ''
          const profileRoute = '/api/v1/users/@me/profile'
          const profileEmail = 'phamhanst4@gmail.com'
          const profilePassword = '475_DienBienPhu'
          beforeAll(async () => {
            await databaseService.connect()
            const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst4@gmail.com', password: '475_DienBienPhu' })
            accessToken = response.body.data.access_token
          })   
                // Test case for successful profile retrieval
                it('should return 200 and the user profile when a valid token is provided', async () => {
                  const response = await request(app).get(profileRoute).set('Authorization', `Bearer ${accessToken}`);
                  expect(response.status).toBe(StatusCodes.OK);
                  expect(response.body).toEqual({
                    statusCode: 200,
                    message: 'The user account information was successfully retrieved.',
                    data: {
                        _id: expect.any(String),
                        full_name: 'Nguyen Van A',
                        email: 'phamhanst4@gmail.com',
                        phone: '0915151512',
                        role: 'User',
                        gender: null,
                        failedLoginAttempts: 0,
                        address: '',
                        avatar: '',
                        thumbnail: '',
                        isOnline: false,
                        isBlocked: false,
                        isPro: false,
                        report_count: 0,
                        lastFailedLoginAttempt: null,
                        _destroy: false,
                        password_change_at: null,
                        created_at: expect.any(String),
                        updated_at: null
                    },
                      dateTime: expect.any(String)
                    })
                })
              
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
                    })
             })
         })


//Test case for get all users
//   describe('GET /api/v1/auth/users', () => {
//     const getUsersRoute = '/api/v1/auth/users';

//     //return 200 if users are retrieved successfully 
//     it('should return 200 OK if users are retrieved successfully', async () => {
//       //log in first as adminstrator
//       const response = await request(app).get(getUsersRoute).set('Authorization', `Bearer ${mockToken}`); // Assuming authorization is required
//       expect(response.status).toBe(StatusCodes.OK);
//       expect(response.body).toEqual({
//         statusCode: StatusCodes.OK,
//         message: 'Get all users successfully.', //truong hop co 3 doi tuong trong he thong :PASS//
//         data: [
//             {
//               _id: '6686af7bfe32c4f1590c2810',
//               full_name: 'New User Name',
//               email: 'phamhanst20@gmail.com',
//               phone: '0774567890',
//               role: 'Admin',
//               gender: 'Male',
//               verify: 'Verified',
//               failedLoginAttempts: 0,
//               address: '',
//               avatar: 'newavatar.png',
//               thumbnail: 'newthumbnail.png',
//               isOnline: false,
//               isBlocked: false,
//               lastFailedLoginAttempt: null,
//               _destroy: false,
//               password_change_at: expect.any(String),
//               created_at: expect.any(String),
//               updated_at: expect.any(String)
//             },
//             {
//               _id: '6687943ac85fadd74ecdb878',
//               full_name: 'HanP',
//               email: 'phamhanst1@gmail.com',
//               phone: '0901123132',
//               role: 'User',
//               gender: null,
//               verify:'Unverified',
//               failedLoginAttempts: 0,
//               address: '',
//               avatar: '',
//               thumbnail: '',
//               isOnline: false,
//               isBlocked: false,
//               lastFailedLoginAttempt: null,
//               _destroy: false,
//               password_change_at: expect.any(String),
//               created_at: expect.any(String),
//               updated_at: expect.any(String)
//             },
//             {
//               _id: '66a112b058a138e5d150f29f',
//               full_name: 'Duong Quoc Nam',
//               email: 'duongquocnam224400@gmail.com',
//               phone: '0917565819',
//               role: 'Admin',
//               gender: null,
//               verify: 'Verified',
//               failedLoginAttempts: 0,
//               address: '',
//               avatar: '',
//               thumbnail: '',
//               isOnline: false,
//               isBlocked: false,
//               lastFailedLoginAttempt: null,
//               _destroy: false,
//               password_change_at: expect.any(String),
//               created_at: expect.any(String),
//               updated_at: expect.any(String)
//             },
//             {
//               _id: '670a92209cd4b451fd2b71f0',
//               full_name: 'Test User',
//               email: 'phamhanst333@gmail.com',
//               phone: '0775541231',
//               role: 'User',
//               gender: null,
//               verify: 'Verified',
//               failedLoginAttempts: 0,
//               address: '',
//               avatar: '',
//               thumbnail: '',
//               isOnline: false,
//               isBlocked: false,
//               isPro: false,
//               report_count: 0,
//               lastFailedLoginAttempt: null,
//               _destroy: false,
//               password_change_at: null,
//               created_at: expect.any(String),
//               updated_at: null
            
//             }],
//           dateTime: expect.any(String)
//   })
        
// })

//       //return 401 if no token is provided
//       it('should return 401 Unauthorized if no token is provided', async () => {  
//             const response = await request(app).get(getUsersRoute); // No Authorization header provided
//             expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
//             expect(response.body).toEqual({
//                       message: 'You must be logged in to continue.',
//                       created_at: expect.any(String),
//                       updated_at: expect.any(String),
//                       messageConstants: null,
//                       name: 'ErrorWithStatus'  
//                     });
//             })
       
//        //Return 403 if non-admin tries to access the route     
//       it('should return 403 Forbidden if a non-admin user tries to access the route', async () => {
//           const response = await request(app).get(getUsersRoute).set('Authorization', `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NzBhOTIyMDljZDRiNDUxZmQyYjcxZjAiLCJlbWFpbCI6InBoYW1oYW5zdDMzM0BnbWFpbC5jb20iLCJyb2xlIjoiVXNlciIsInRva2VuX3R5cGUiOiJBY2Nlc3NUb2tlbiIsImlhdCI6MTcyODc0NjAxNiwiZXhwIjoxNzM3Mjk5NjE2fQ.JlrVj4LO-YcUIR8gbYMkD24hwb1mFvvA9t10k5zdFhw`); // Non-admin token provided
//               expect(response.status).toBe(StatusCodes.FORBIDDEN);
//               expect(response.body).toEqual({
//                 message: 'You do not have the necessary permissions for this action.',
//                 created_at: expect.any(String),
//                 updated_at: expect.any(String),
//                 messageConstants: null,
//                 name: 'ErrorWithStatus'
//               })
//           })          
          
//           })

//Test case for get users by role
  //  describe('GET /api/v1/auth', () => {
  //     const getUsersByRoleRoute = '/api/v1/auth';
  
  //     // Test case for 200 OK when valid role is provided
  //     it('should return 200 OK if users with valid roles are retrieved successfully', async () => {
  //         // const response = await request(app).get(getAuthUsersRoute).set('Authorization', `Bearer ${mockToken}`); // Assuming authorization is required
  //         const response = await request(app).get(getUsersByRoleRoute).query({ page: 1, limit: 10, role: 'User' }).set('Authorization', `Bearer ${mockToken}`); // Sending query params for pagination and role filtering.set('Authorization', `Bearer ${adminToken}`); // Assuming admin token is required

  //         expect(response.status).toBe(StatusCodes.OK);
  //         expect(response.body).toEqual({
  //             statusCode: StatusCodes.OK,
  //             message: 'Successfully target users by role.',
  //               data: {
  //                 items: [
  //              {
  //             _id: '6687943ac85fadd74ecdb878',
  //             full_name: 'HanP',
  //             email: 'phamhanst1@gmail.com',
  //             phone: '0901123132',
  //             role: 'User',
  //             gender: null,
  //             verify: 'Unverified',
  //             failedLoginAttempts: 0,
  //             address: '',
  //             avatar: '',
  //             thumbnail: '',
  //             isOnline: false,
  //             isBlocked: false,
  //             lastFailedLoginAttempt: null,
  //             _destroy: false,
  //             password_change_at: expect.any(String),
  //             created_at: expect.any(String),
  //             updated_at: expect.any(String)
  //                },
  //                {
  //                   _id: '670a92209cd4b451fd2b71f0',
  //                   full_name: 'Test User',
  //                   email: 'phamhanst333@gmail.com',
  //                   phone: '0775541231',
  //                   role: 'User',
  //                   gender: null,
  //                   verify: 'Verified',
  //                   failedLoginAttempts: 0,
  //                   address: '',
  //                   avatar: '',
  //                   thumbnail: '',
  //                   isOnline: false,
  //                   isBlocked: false,
  //                   isPro: false,
  //                   report_count: 0,
  //                   lastFailedLoginAttempt: null,
  //                   _destroy: false,
  //                   password_change_at: null,
  //                   created_at: expect.any(String),
  //                   updated_at: null
  //                 }
  //               ],
  //               page: 1,
  //               per_page: 10,
  //               total_pages: 1,
  //               total_items: 2
  //             },
  //              dateTime: expect.any(String)
  //     })
  //     })
  
  //     // Test case for 401 Unauthorized if no token is provided
  //     it('should return 401 Unauthorized if no token is provided', async () => {
  //       const response = await request(app).get(getUsersByRoleRoute).query({ page: 1, limit: 10, role: 'User' })
  //       expect(response.status).toBe(StatusCodes.UNAUTHORIZED);  
  //       expect(response.body).toEqual({
  //           message: 'You must be logged in to continue.',
  //           created_at: expect.any(String),
  //           updated_at: expect.any(String),
  //           messageConstants: null,
  //           name: 'ErrorWithStatus'
  //         })
  //     })
         
  //     // Test case for 403 Forbidden if non-admin tries to access the route
  //     it('should return 403 Forbidden if non-admin tries to access the route', async () => {
  //       const response = await request(app).get(getUsersByRoleRoute).query({ page: 1, limit: 10, role: 'User' }).set('Authorization', `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NzBhOTIyMDljZDRiNDUxZmQyYjcxZjAiLCJlbWFpbCI6InBoYW1oYW5zdDMzM0BnbWFpbC5jb20iLCJyb2xlIjoiVXNlciIsInRva2VuX3R5cGUiOiJBY2Nlc3NUb2tlbiIsImlhdCI6MTcyODc1NDA2NSwiZXhwIjoxNzM3MzA3NjY1fQ.dEqLd_DfkV7wIjrsAaRdrmTa8rbO1d5fuzS2q32kZGc`);
  //       expect(response.status).toBe(StatusCodes.FORBIDDEN);
  //       expect(response.body).toEqual({
  //         message: 'You do not have the necessary permissions for this action.',
  //         created_at: expect.any(String),
  //         updated_at: expect.any(String),
  //         messageConstants: null,
  //         name: 'ErrorWithStatus'
  //       })
  //     })

  //           })

  //test case for get all banner          
  //  describe('GET /api/v1/banners', () => {
  //             const GetBannersRoute = '/api/v1/banners';
            

  //        //return 200 and an array of banners     
  //             it('should return 200 and an array of banners if successful', async () => {
  //               const response = await request(app).get(GetBannersRoute);
  //               expect(response.status).toBe(StatusCodes.OK);
  //               expect(response.body).toEqual({
  //                 statusCode: StatusCodes.OK,
  //                 message: 'All banners in the database have been successfully retrieved.',
  //                 data: [
  //                   {
  //                     _id: expect.any(String),
  //                     url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/iyxuvvoqqnhdxk8bq2va.jpg',
  //                     slug: 'thanh-long-viet-nam',
  //                     description: 'Hàng Việt Nam chất lượng cao',
  //                     link: ''
  //                   },
  //                   {
  //                     _id: expect.any(String),
  //                     url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/cmvvfly7owavf51axtuw.jpg',
  //                     slug: 'grapes',
  //                     description: 'aaaaaaaa',
  //                     link: ''
  //                   }
  //                 ],
  //                  dateTime: expect.any(String)
  //               })
  //             })
            
                
  //             //reuturn 200 if no banners are found
  //             it('should return 200 if no banners are found', async () => {
  //               const response = await request(app).get(GetBannersRoute).set('Authorization', `Bearer ${mockToken}`);
  //               expect(response.status).toBe(StatusCodes.OK);
  //               expect(response.body).toEqual({
  //                statusCode: StatusCodes.OK,
  //                 message: 'All banners in the database have been successfully retrieved.',
  //                 data: [],
  //                 dateTime: expect.any(String)
  //                 })
  //            })
            
  //             // it('should return 500 Internal Server Error if a database error occurs', async () => {
  //             //   const mockErrorMessage = 'Database error';
  //             //   const response = await request(app).get(GetBannersRoute).set('Authorization', `Bearer ${mockToken}`);
  //             //   expect(response.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
  //             //   expect(response.body).toEqual({
  //             //     statusCode: StatusCodes.INTERNAL_SERVER_ERROR,
  //             //       message: 'Internal server error',
  //             //       messages: '',
  //             //       dateTime: '2024-06-22T00:00:00.000Z'
  //             //   })
  //             // })
  //           })
  
    //test case for create banner
    // describe('POST /api/v1/banners', () => {
    //   let accessToken = ''
    //   beforeAll(async () => {
    //     await databaseService.connect()
    //     const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst4@gmail.com', password: '475_DienBienPhu' })
    //     accessToken = response.body.data.access_token
    //   }) 
    //   const createBannerRoute = '/api/v1/banners';
    //   const createBannerPayload = {slug: 'grapes',description: 'aaaaaaaa',url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/cmvvfly7owavf51axtuw.jpg'};
    //   //test case for 200 if banner created successfully
    //   it('should return 200 OK if banner created successfully', async () => {
    //     const response = await request(app).post(createBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(createBannerPayload);
    //     expect(response.status).toBe(StatusCodes.CREATED);
    //     expect(response.body).toEqual({  
    //       statusCode: StatusCodes.CREATED,
    //       message: 'Banner successfully inserted.',
    //       data: {
    //         acknowledged: true,
    //         insertedId: expect.any(String)
    //       },
    //       dateTime: expect.any(String)
    //              })    
    //          })
        
    //   //should return 401 Unauthorized if no token is provided
    //          it('should return 401 Unauthorized if no token is provided', async () => {
    //           const response = await request(app).post(createBannerRoute).send(createBannerPayload);
    //           expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
    //           expect(response.body).toEqual({
    //             message: 'You must be logged in to continue.',
    //             created_at: expect.any(String),
    //             updated_at: expect.any(String),
    //             messageConstants: null,
    //             name: "ErrorWithStatus"
    //           })
    //         })

    //  //should reuturn 401 if the token is invaid       
    //  it('should return 401 Unauthorized if the token is invaid', async () => {
    //         const response = await request(app).post(createBannerRoute).set('Authorization', 'Bearer invalidToken').send(createBannerPayload);
    //         expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
    //         expect(response.body).toEqual({
    //           message: 'jwt malformed',
    //           created_at: expect.any(String),
    //           updated_at: expect.any(String),
    //           messageConstants: null,
    //           name: "ErrorWithStatus"
    //         })
    //       })    
              
    //   //should return 403 Forbidden if the user is not an admin
    //     it('should return 403 Forbidden if the user is not an admin', async () => {
    //       const response = await request(app).post(createBannerRoute).set('Authorization', `Bearer ${accessToken}`).send(createBannerPayload);         
    //       expect(response.status).toBe(StatusCodes.FORBIDDEN);
    //       expect(response.body).toEqual({
    //         message: 'You do not have the necessary permissions for this action.',
    //         created_at: expect.any(String),
    //         updated_at: expect.any(String),
    //         messageConstants: null,
    //         name: 'ErrorWithStatus'
    //       })
    //     })
        
    //   //should return 400 if URL is invalid
    //   it('should return 400 if URL is invalid', async () => {
    //     const invalidUrlPayload = {
    //       slug: 'Supermarket', //change slug everytimes testing to avoid duplicate slug
    //       description: 'string',
    //       url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1719218378/photo/m9qt9aodgpuzbqretpda.doc'
    //     }
      
    //     const response = await request(app).post(createBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidUrlPayload);
    //     expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
    //     expect(response.body.errors).toEqual({        
    //             url: {
    //               type: 'field',
    //               value: invalidUrlPayload.url,
    //               msg: 'Image URL must end with .jpeg, .jpg, or .png.',
    //               path: 'url',
    //               location: 'body'
    //                 }
    //            })
    //       })

    //   //should return 400 if missing slug field
    //   it('should return 400 if slug field is empty', async () => {
    //     const missingSlugPayload = {
    //       slug: '',  //slug field is empty
    //       description: 'string',
    //       url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1719218378/photo/m9qt9aodgpuzbqretpda.png'
    //     }
    //     const response = await request(app).post(createBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(missingSlugPayload);
    //     expect(response.status).toBe(StatusCodes.BAD_REQUEST);
    //     expect(response.body.errors).toEqual({
    //             slug: {
    //               type: 'field',
    //               value: '',
    //               msg: 'Banner slug is required.',
    //               path: 'slug',
    //               location: 'body'
    //              }
    //           })    
    //          })
     
    //  //should return 409 if slug already exists
    //  it('should return 409 if slug already exists', async () => {
    //      const duplicateSlugPayload = {
    //           slug: 'grapes', //slug already exists
    //           description: 'string',
    //           url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1719218378/photo/m9qt9aodgpuzbqretpda.png'
    //   }
    //   const response = await request(app).post(createBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(duplicateSlugPayload); 
    //   expect(response.status).toBe(StatusCodes.CONFLICT);
    //   expect(response.body).toEqual({
    //         statusCode: StatusCodes.CONFLICT,
    //         message: 'Slug already exists. Please use a unique slug.',
    //         data: duplicateSlugPayload.slug,
    //         datetime: expect.any(String)
    //             })
    //      })
    // })

//     //test case for update banner
    
  describe('PUT /api/v1/banners', () => {
      let updateToken = ''
      const updateBannerRoute = '/api/v1/banners/66953cfada2d869d053fe30a'// Assume slug 'grapes' for updating
      const updateBannerPayload = {
                slug: 'Thanh Long Do zzz',//Change slug everytime test to avoid duplicate slug
                url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.jpg',
                description: 'string',
                link: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh'
      }
            
        beforeAll(async () => {
          await databaseService.connect()
          const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst4@gmail.com', password: '475_DienBienPhu' })
          updateToken = response.body.data.access_token
        })
    
      // Test case: should return 409 if slug already exists
      it('should return 409 if slug already exists', async () => {
        const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(updateBannerPayload);          
        expect(response.status).toBe(StatusCodes.CONFLICT);
        expect(response.body.errors).toEqual({
                slug: {
                  type: 'field',
                  msg: 'Slug already exists in the system.',
                  path: 'slug',
                  location: 'body'
                }
            })
          })   
              
    
      // Test case: should return 401 if no token is provided
      it('should return 401 Unauthorized if no token is provided', async () => {
        const response = await request(app).put(updateBannerRoute).send(updateBannerPayload);
        expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
        expect(response.body).toEqual({
          message: 'You must be logged in to continue.',
          created_at: expect.any(String),
          updated_at: expect.any(String),
          messageConstants: null,
          name: 'ErrorWithStatus'
        })
      })
    
      // Test case: should return 403 if the user is not an admin
      it('should return 403 Forbidden if the user is not an admin', async () => {
        const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${updateToken}`).send(updateBannerPayload);
        expect(response.status).toBe(StatusCodes.FORBIDDEN);
        expect(response.body).toEqual({
          message: 'You do not have the necessary permissions for this action.',
          created_at: expect.any(String),
          updated_at: expect.any(String),
          messageConstants: null,
          name: 'ErrorWithStatus'
        });
      });
    
      // Test case: should return 400 if URL is invalid
      it('should return 400 if URL is invalid', async () => {
        const invalidUrlPayload = {
          slug: 'Thanh Long Do',
          url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.doc',
          description: 'string',
          link: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh'
        }
    
        const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidUrlPayload);
        
        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
            url: {
            type: 'field',
            value: invalidUrlPayload.url,
            msg: 'Image URL must end with .jpeg, .jpg, or .png.',
            path: 'url',
            location: 'body'
          }
        })
      })
    
      // Test case: should return 400 if ID banner is invalid
      it('should return 400 if ID banner is invalid', async () => {
        const invalidBannerRoute = '/api/v1/banners/Hutech@123';
        const response = await request(app).put(invalidBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(updateBannerPayload);
        
        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
              id: {
                  type: 'field',
                  value: 'Hutech@123',
                  msg: 'Invalid banner ID.',
                  path: 'id',
                  location: 'params'
                   }
                })
           })
    
    //test case should return 404 if ID banner non-exists
    
    it('should return 404 if banner not found', async () => {
      const nonExistentBannerRoute = '/api/v1/banners/66953cfada2d869d053fe30d';
      const response = await request(app).put(nonExistentBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(updateBannerPayload);
      
      expect(response.status).toBe(StatusCodes.BAD_REQUEST);
      expect(response.body.errors).toEqual({
            id: {
                type: 'field',
                value: '66953cfada2d869d053fe30d',
                msg: 'Banner not found or has been deleted.',
                path: 'id',
                location: 'params'
                 }
              })
         })

//test case should return 400 if link banner is wrong format
         it('should return 400 if link banner is wrong format', async () => {
          const invalidLinkPayload = {
                    slug: 'Sau Rieng thom ngon',
                    url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.png',
                    description: 'string',
                    link: 'zzzzzzzzzzzzzzzz'
          }
          
          const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidLinkPayload);
          expect(response.status).toBe(StatusCodes.BAD_REQUEST);
          expect(response.body.errors).toEqual({
                    link: {
                      type: 'field',
                      value: invalidLinkPayload.link,
                      msg: 'Invalid link format. Please provide a valid URL.',
                      path: 'link',
                      location: 'body'
                     }
                  })
             })

//test case should return 400 if link banner is Url
          it('should return 400 if link banner is Url', async () => {
            const invalidLinkPayload = {
                      slug: 'Sau Rieng thom ngon',
                      url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.png',
                      description: 'string',
                      link: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1720197825/avatar/iwdsqojke1mxj0bla6r2.jpg'
            }
            
            const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidLinkPayload);
            expect(response.status).toBe(StatusCodes.BAD_REQUEST);
            expect(response.body.errors).toEqual({
                 link: {
                        type: 'field',
                        value: invalidLinkPayload.link,
                        msg: 'Invalid link format. Please provide a valid URL.',
                        path: 'link',
                        location: 'body'
                    
                      }
                    })
              })

          
        // Test case: should return 400 if slug field is empty
        it('should return 400 if slug field is empty', async () => {
          const missingDescriptionPayload = {
                  slug: '',
                  url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.png',
                  description: 'string',
                  link: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh'
          }
    
        const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(missingDescriptionPayload);
        
        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
                    slug: {
                      type: 'field',
                      value: '',
                      msg: 'Banner slug is required.',
                      path: 'slug',
                      location: 'body'
                    }
             })
      })

 // Test case: should return 400 if URL field is empty
        it('should return 400 if URL field is empty', async () => {
          const missingURLPayload = {
                  slug: 'Ca Chua thom ngon',
                  url: '',
                  description: 'string',
                  link: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh'
          }

        const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(missingURLPayload);

        expect(response.status).toBe(StatusCodes.BAD_REQUEST);
        expect(response.body.errors).toEqual({
                    url: {
                      type: 'field',
                      value: '',
                      msg: 'Image URL is required.',
                      path: 'url',
                      location: 'body'
                              }
            })
        })

            // Test case: should return 400 if description field is empty
            it('should return 400 if  description is empty', async () => {
              const missingDescriptionPayload = {
                      slug: 'Ca Chua thom ngon',
                      url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.png',
                      description: '',
                      link: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh'
              }

            const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(missingDescriptionPayload);

            expect(response.status).toBe(StatusCodes.BAD_REQUEST);
            expect(response.body.errors).toEqual({
                          description: {
                            type: 'field',
                            value: '',
                            msg: 'Description is required.',
                            path: 'description',
                            location: 'body'
                                  }
                })
            })


            // Test case: should return 400 if link field is empty
            it('should return 400 if  link is empty', async () => {
              const missingLinkPayload = {
                      slug: 'Ca Chua thom ngon',
                      url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.png',
                      description: 'aaaaaaaaaaaaaaa',
                      link: ''
              }

            const response = await request(app).put(updateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(missingLinkPayload);

            expect(response.status).toBe(StatusCodes.BAD_REQUEST);
            expect(response.body.errors).toEqual({
                                link: {
                                  type: 'field',
                                  value: '',
                                  msg: 'Banner link is required.',
                                  path: 'link',
                                  location: 'body'
                                }   
                   })
            })

      
//Test case: should return 200 if updated banner successfully
        it('should return 200 if updated banner successfully', async () => {
          const newUpdateBannerRoute = '/api/v1/banners/66abbd8aac454710ab7929a0'
            
          
          const newUpdateBannerPayload = {
                      slug: 'Ca Chua thom ngon',//rememeber to change slug 
                      url: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1722531140/photo/updated_image.png',
                      description: 'aaaaaaaaaaaaaaa',
                      link: 'https://vi.wikipedia.org/wiki/Trang_Ch%C3%ADnh'
          }

          const response = await request(app).put(newUpdateBannerRoute).set('Authorization', `Bearer ${mockToken}`).send(newUpdateBannerPayload);
          
          expect(response.status).toBe(StatusCodes.OK);
          expect(response.body.errors).toEqual({
                  slug: {
                    type: 'field',
                    value: newUpdateBannerPayload.slug,
                    msg: 'Slug already exists in the system.',
                    path: 'slug',
                    location: 'body'
                    }
                })
            })
      

        })
    
    //test case for delete banner    
    describe('DELETE /api/v1/banners', () => {
      let deleteToken  = ''
      const deleterBannerRoute = '/api/v1/banners/671be17be59e923ac4c877c8' //change id banner everytime delete
      beforeAll(async () => {
        await databaseService.connect()
        const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst4@gmail.com', password: '475_DienBienPhu' })
        deleteToken = response.body.data.access_token
      })

      //test case for return 200 if delete banner successfully
      it('should return 200 OK if banner is deleted successfully', async () => {
        const response = await request(app).delete(deleterBannerRoute).set('Authorization', `Bearer ${mockToken}`);
    
        expect(response.status).toBe(StatusCodes.OK);
        expect(response.body).toEqual({
          statusCode: 200,
          message: 'Banner successfully deleted.',
          data: '',
          dateTime: expect.any(String)
        })
      })

// Test case: should return 404 if ID banner does not exist
        it('should return 404 if ID banner does not exist', async () => {
          const nonExistentBannerRoute = '/api/v1/banners/671bdba4abd5f1ea11dec41f' // ID không tồn tại
          const response = await request(app).delete(nonExistentBannerRoute).set('Authorization', `Bearer ${mockToken}`);
          
          expect(response.status).toBe(StatusCodes.NOT_FOUND); // Kiểm tra mã trạng thái là 404
          expect(response.body.errors).toEqual({
              id: {
                  type: 'field',
                  value: '671bdba4abd5f1ea11dec41f', // ID không tồn tại
                  msg: 'Banner not found or has been deleted.', // Thông điệp lỗi
                  path: 'id',
                  location: 'params'
              }
          })
        })

        //test case for return 400 if ID banner is invalid
        it('should return 400 if ID banner is invalid', async () => {
          const invalidBannerRoute = '/api/v1/banners/671bdba4abd5f'
          const response = await request(app).delete(invalidBannerRoute).set('Authorization', `Bearer ${mockToken}`);
        
          expect(response.status).toBe(StatusCodes.BAD_REQUEST);
          expect(response.body.errors).toEqual({
                    id: { 
                      type: 'field',
                      value: '671bdba4abd5f',
                      msg: 'Invalid banner ID.',
                      path: 'id',
                      location: 'params'
                    }
              })      
          })
  
          // Test case: should return 401 if no token is provided
          it('should return 401 Unauthorized if no token is provided', async () => {
            const response = await request(app).delete(deleterBannerRoute);
            expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
            expect(response.body).toEqual({
              message: 'You must be logged in to continue.',
              created_at: expect.any(String),
              updated_at: expect.any(String),
              messageConstants: null,
              name: 'ErrorWithStatus'
            })
          })

          // Test case: should return 403 if the user is not an admin
          it('should return 403 Forbidden if the user is not an admin', async () => {
            const response = await request(app).delete(deleterBannerRoute).set('Authorization', `Bearer ${deleteToken}`);//token of user not an admin
            expect(response.status).toBe(StatusCodes.FORBIDDEN);
            expect(response.body).toEqual({
              message: 'You do not have the necessary permissions for this action.',
              created_at: expect.any(String),
              updated_at: expect.any(String),
              messageConstants: null,
              name: 'ErrorWithStatus'
            });
          })
 
        })
        
        describe('GET /api/v1/categories', () => {
          const GetCategoriesRoute = '/api/v1/categories';
      
          // return 200 and an array of categories
          it('should return 200 and an array of categories if successful', async () => {
              const response = await request(app).get(GetCategoriesRoute);
              expect(response.status).toBe(StatusCodes.OK);
              expect(response.body).toEqual({
                  statusCode: StatusCodes.OK,
                  message: 'All categories have been successfully retrieved.',
                  data: [
                      {
                          _id: '6695d79e607995c4144ec448',
                          name: 'Vegetable',
                          slug: 'vegetable',
                          items: [],
                          image: ''
                      },
                      {
                        _id: '6695d98bc4fe0075232c86e2',
                        name: 'Fruits',
                        slug: 'fruits',
                        items: [],
                        image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/iyxuvvoqqnhdxk8bq2va.jpg'
                      },
                      {
                        _id: '66b3968133caf396daf14eb3',
                        name: 'zxzxczcx',
                        slug: 'zxzxczcx',
                        items: [],
                        image: ''
                      }
                    ],
                  dateTime: expect.any(String)
              })
          })
      
          // return 200 if no categories are found
          it('should return 200 if no categories are found', async () => {
              const response = await request(app).get(GetCategoriesRoute).set('Authorization', `Bearer ${mockToken}`);
              expect(response.status).toBe(StatusCodes.OK);
              expect(response.body).toEqual({
                  statusCode: StatusCodes.OK,
                  message: 'All categories have been successfully retrieved.',
                  data: [],
                  dateTime: expect.any(String)
              })
          })
      })
     
      describe('POST /api/v1/categories', () => {
        const createCategoryRoute = '/api/v1/categories';
    
        // Return 201 and the created category
        it('should return 201 and the created category if successful', async () => {
            const newCategory = {
                name: 'Electronics',//Change name everytimes testing to avoid duplicate name
                image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/electronics.jpg'
            }
    
            const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(newCategory);
            expect(response.status).toBe(StatusCodes.CREATED);
            expect(response.body).toEqual({
                statusCode: StatusCodes.CREATED,
                message: 'Category successfully inserted.',
                    data: {
                      _id: expect.any(String),
                      name: newCategory.name,
                      slug: 'electronics',
                      items: [],
                      image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/electronics.jpg',
                      creator_id: expect.any(String),
                      updater_id: null,
                      created_at: expect.any(String),
                      updated_at: expect.any(String),
                      _destroy: false
                    },
                dateTime: expect.any(String)
            })
        })
    
        // Return 400 if name fields is empty
        it('should return 400 if name field is empty', async () => {
            const incompleteCategory = {
                name: '',
                image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/electronics.jpg'
            };
    
            const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(incompleteCategory);
            expect(response.status).toBe(StatusCodes.BAD_REQUEST);
            expect(response.body.errors).toEqual({
                  name: {
                      type: 'field',
                      value: '',
                      msg: 'Category name is required.',
                      path: 'name',
                      location: 'body'
                    }
                })
        })
    
             // 201 created successfull if image field is empty
        it('should return 201 created successfull if image field is empty', async () => {
          const incompleteCategory = {
              name: 'string',
              image: ''
          };
  
          const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(incompleteCategory);
          expect(response.status).toBe(StatusCodes.CREATED);
          expect(response.body).toEqual({
                  statusCode: StatusCodes.CREATED,
                  message: 'Category successfully inserted.',
                  data: {
                    _id: expect.any(String),
                    name: incompleteCategory.name,
                    slug: 'string',
                    items: [],
                    image: '',
                    creator_id: expect.any(String),
                    updater_id: null,
                    created_at: expect.any(String),
                    updated_at: expect.any(String),
                    _destroy: false
                  },
                  dateTime: expect.any(String)
          })
      })

        // Return 401 if unauthorized
              it('should return 401 if user is not authorized', async () => {
                  const newCategory = {
                      name: 'Unauthorized Category',
                      image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/unauthorized.jpg'
                  };
          
                  const response = await request(app).post(createCategoryRoute).send(newCategory);
          
                  expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
                  expect(response.body).toEqual({
                    message: "You must be logged in to continue.",
                    created_at:  expect.any(String),
                    updated_at:  expect.any(String),
                    messageConstants: null,
                    name: "ErrorWithStatus"
                  })
              })


      //should return 400 if name cannot be empty or contain only whitespace        
   it('should return 400 if name cannot be empty or contain only whitespace', async () => {
         const invalidCategory = {
              name: 'Nho   Nho', // Tên chứa khoảng trắng lớn
              image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/invalid.jpg'
                };
        
         const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
                expect(response.status).toBe(StatusCodes.BAD_REQUEST);
                expect(response.body.errors).toEqual({
                    name: {
                      type: 'field',
                      value: invalidCategory.name,
                      msg: 'Category name cannot contain multiple consecutive spaces.',
                      path: 'name',
                      location: 'body'
                        }   
                 })
          }) 
          
          
          //Should return 409 if name already exists
          it('should return 409 if name already exists', async () => {
            const duplicateCategory = {
                name: 'Electronics', // Tên đã tồn tại trong cơ sở dữ liệu
                image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/electronics.jpg'
            };
    
            await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(duplicateCategory);
            const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(duplicateCategory);
            expect(response.status).toBe(StatusCodes.CONFLICT);
            expect(response.body.errors).toEqual({
                  name: {
                    type: 'field',
                    value: duplicateCategory.name,
                    msg: 'This category name already exists.',
                    path: 'name',
                    location: 'body'
                  }
             })
          })


         //should return 422 if name field is invalid 
          it('should return 422 if name field is invalid', async () => {
            const invalidCategory = {
                name: 'Electronics@123!', // Tên chứa ký tự không hợp lệ
                image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/invalid.jpg'
            };
    
            const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
            expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
            expect(response.body.errors).toEqual({
              name: {
                type: 'field',
                value: invalidCategory.name,
                msg: 'Invalid category name format.',
                path: 'name',
                location: 'body'
                 } 
                })
          })
          
          
               //should return 422 if name field is too long
          it('should return 422 if name field is too long', async () => {
            const invalidCategory = {
                name: 'sssssssssssssssssssssssssssszzzzzzzzzzzzzzzzzzzs', // Tên chứa ký tự tren 30 ky tự
                image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/invalid.jpg'
            };
    
            const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
            expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
            expect(response.body.errors).toEqual({
              name: {
                type: 'field',
                value: invalidCategory.name,
                msg: "Category name must be between 2 and 30 characters.",
                path: "name",
                location: "body"
                 } 
                })
          })



          // Return 422 if "image" field is invalid
    it('should return 422 if image field is invalid', async () => {
      const invalidCategory = {
          name: 'Valid Name',
          image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/electronics.doc' // URL không hợp lệ
      };

      const response = await request(app).post(createCategoryRoute).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
      expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
      expect(response.body.errors).toEqual({
              image: {
                  type: 'field',
                  value: invalidCategory.image,
                  msg: 'Category image must be a valid URL.',
                  path: 'image',
                  location: 'body'
                }
         })        
        })

    })            
 

  //  test case for delete categories 
    describe('DELETE /api/v1/categories', () => {
      let deleteCateToken = '';
      const deleteCategoryRoute = '/api/v1/categories?id=6695d79e607995c4144ec448'; // Change ID everytimes test
  
      beforeAll(async () => {
          await databaseService.connect();
          const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst4@gmail.com', password: '475_DienBienPhu' });
          deleteCateToken = response.body.data.access_token;
      });
  
      // Test case: should return 204 OK if category is deleted successfully
      it('should return 204 OK if category is deleted successfully', async () => {
          const response = await request(app).delete(deleteCategoryRoute).set('Authorization', `Bearer ${mockToken}`);
          expect(response.status).toBe(StatusCodes.NO_CONTENT);
          expect(response.body).toEqual({}); 
        
        });
  
  
    // Test case: should return 404 if ID category invalid
            it('should return 404 if ID category invalid', async () => {
              const invalidCategoryRoute = '/api/v1/categories/671bdba4abd5f1'; // ID không tồn tại
              const response = await request(app).delete(invalidCategoryRoute).set('Authorization', `Bearer ${mockToken}`);
              expect(response.status).toBe(StatusCodes.NOT_FOUND);
              expect(response.body.errors).toEqual({
                  id: {
                      type: 'field',
                      value: '671bdba4abd5f1', // ID invalid
                      msg: 'Invalid category ID.', // Error message
                      path: 'id',
                      location: 'query'
                  }
              })
            })

    // Test case: should return 404 if ID category non-exists
            it('should return 404 if ID category non-exists', async () => {
              const invalidCategoryRoute = '/api/v1/categories/97603da4-8152-4cf9-8177-dc9d5e6bfc73'; // ID non-exists
              const response = await request(app).delete(invalidCategoryRoute).set('Authorization', `Bearer ${mockToken}`);
              expect(response.status).toBe(StatusCodes.NOT_FOUND);
              expect(response.body.errors).toEqual({
                  id: {
                      type: 'field',
                      value: '97603da4-8152-4cf9-8177-dc9d5e6bfc73', // ID non-exists
                      msg: 'Invalid category ID.', // Error message
                      path: 'id',
                      location: 'query'
                  }
              })
            })
           
           
            // Test case: should return 401 Unauthorized if no token is provided
            it('should return 401 Unauthorized if no token is provided', async () => {
              const deleteCategoryRoute = '/api/v1/categories/671be17be59e923ac4c877c8'; // ID valid
              const response = await request(app).delete(deleteCategoryRoute); // No prodive toke
              
              expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
              expect(response.body).toEqual({
                  message: 'You must be logged in to continue.',
                  created_at: expect.any(String),
                  updated_at: expect.any(String),
                  messageConstants: null,
                  name: 'ErrorWithStatus'
              });
            });


            // Test case: should return 403 Forbidden if the user is not an admin
                it('should return 403 Forbidden if the user is not an admin', async () => {
                  const deleteCategoryRoute = '/api/v1/categories/671be17be59e923ac4c877c8'; // ID valid
                  const response = await request(app).delete(deleteCategoryRoute).set('Authorization', `Bearer ${deleteCateToken}`); // Token của user không phải admin                  
                  expect(response.status).toBe(StatusCodes.FORBIDDEN);
                  expect(response.body).toEqual({
                      message: 'You do not have the necessary permissions for this action.',
                      created_at: expect.any(String),
                      updated_at: expect.any(String),
                      messageConstants: null,
                      name: 'ErrorWithStatus'
                  });
                });

 
        })

  //test case for update categories
  describe('PUT /api/v1/categories', () => {
    const updateCategoryRoute = (id) => `/api/v1/categories/${id}`;
    const mockCategoryId = '6695d79e607995c4144ec448'; // replace with a valid ID for testing

    // Return 200 and the updated category if successful
    it('should return 200 and the updated category if successful', async () => {
        const updatedCategory = {
            name: 'UpdatedElectroniczz', //change name everytimes test
            image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/updated_electronics.jpg'
        };

        const response = await request(app).put(updateCategoryRoute(mockCategoryId)).set('Authorization', `Bearer ${mockToken}`).send(updatedCategory);
        expect(response.status).toBe(StatusCodes.OK);
        expect(response.body).toEqual({
                statusCode: 200,
                message: 'Category has been successfully updated.',
                data: '',
                dateTime: expect.any(String)
          })
    });  

    // Return 422 if name field is empty
    it('should return 422 if name field is empty', async () => {
        const invalidCategory = { name: '', image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/electronics.jpg' };

        const response = await request(app).put(updateCategoryRoute(mockCategoryId)).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
        expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
        expect(response.body.errors).toEqual({
            name: {
                type: 'field',
                value: '',
                msg: 'Category name is required.',
                path: 'name',
                location: 'body'
            }
        });
    });

    // Return 409 if name already exists
    it('should return 409 if name already exists', async () => {
        const duplicateCategory = { 
          name: 'zzzzzzzzzzzzzz', 
          image: '' };
        const response = await request(app).put(`/api/v1/categories/672661c3691d1b8c34305b0d`).set('Authorization', `Bearer ${mockToken}`).send(duplicateCategory);
        expect(response.status).toBe(StatusCodes.CONFLICT);
        expect(response.body.errors).toEqual({
            name: {
                type: 'field',
                value: duplicateCategory.name,
                msg: 'This category name already exists.',
                path: 'name',
                location: 'body'
            }
        });
    });

    // Return 422 if name field is invalid
    it('should return 422 if name field is invalid', async () => {
        const invalidCategory = { name: 'Invalid@Name!', image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/invalid.jpg' };

        const response = await request(app).put(updateCategoryRoute(mockCategoryId)).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
        expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
        expect(response.body.errors).toEqual({
            name: {
                type: 'field',
                value: invalidCategory.name,
                msg: 'Invalid category name format.',
                path: 'name',
                location: 'body'
            }
        });
    });

    // Return 422 if name field is too long
    it('should return 422 if name field is too long', async () => {
        const invalidCategory = { name: 's'.repeat(31), image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/invalid.jpg' };

        const response = await request(app).put(updateCategoryRoute(mockCategoryId)).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
        expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
        expect(response.body.errors).toEqual({
            name: {
                type: 'field',
                value: invalidCategory.name,
                msg: 'Invalid category name format.',
                path: 'name',
                location: 'body'
            }
        });
    });

    // Return 422 if image field is invalid
    it('should return 422 if image field is invalid', async () => {
        const invalidCategory = { name: 'Valid Name', image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/invalid.doc' };

        const response = await request(app).put(updateCategoryRoute(mockCategoryId)).set('Authorization', `Bearer ${mockToken}`).send(invalidCategory);
        expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
        expect(response.body.errors).toEqual({
            image: {
                type: 'field',
                value: invalidCategory.image,
                msg: 'Category image must be a valid URL.',
                path: 'image',
                location: 'body'
            }
        });
    });

    // Return 200 update successfull if image field is empty
    it('should return 200 update successfull if image field is empty', async () => {
      const updatedCategory = {
          name: 'emptyimagesfield', //change name everytimes test
          image: ''
      };

      const response = await request(app).put(`/api/v1/categories/672667fe2dd3f24affdc873e`).set('Authorization', `Bearer ${mockToken}`).send(updatedCategory);
      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body).toEqual({
              statusCode: 200,
              message: 'Category has been successfully updated.',
              data: '',
              dateTime: expect.any(String)
        })
  });  


// Return 422 if both name and image fields are empty
it("should return 422 if both name and image fields are empty", async () => {
  const validCategoryId = '672666d2c93d538762a287b7'; // Replace with a valid category ID for testing
  const updatedCategory = {
      name: '', // Empty name field
      image: '' // Empty image field
  };

  const response = await request(app).put(`/api/v1/categories/${validCategoryId}`).set('Authorization', `Bearer ${mockToken}`).send(updatedCategory);
  expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
  expect(response.body.errors).toEqual({
      name: {
          type: 'field',
          value: '',
          msg: 'Category name is required.',
          path: 'name',
          location: 'body'
      },
    })
});


    // Return 401 if unauthorized
    it('should return 401 if user is not authorized', async () => {
        const newCategory = { name: 'Unauthorized Update', image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/unauthorized.jpg' };

        const response = await request(app).put(updateCategoryRoute(mockCategoryId)).send(newCategory);
        expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
        expect(response.body).toEqual({
            message: "You must be logged in to continue.",
            created_at: expect.any(String),
            updated_at: expect.any(String),
            messageConstants: null,
            name: "ErrorWithStatus"
        });
    });

        // Return 404 if category ID doesn't exist
        it("should return 404 if category ID doesn't exist", async () => {
          const nonexistentId = '5f8f8c44b54764421b7156a0'; // ID that doesn't exist
          const updatedCategory = {
              name: 'Nonexistent Category',
              image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/nonexistent.jpg'
          };

          const response = await request(app).put(`/api/v1/categories/${nonexistentId}`).set('Authorization', `Bearer ${mockToken}`).send(updatedCategory);
          expect(response.status).toBe(StatusCodes.NOT_FOUND);
          expect(response.body.errors).toEqual({
                id: {
                  type: 'field',
                  value: nonexistentId,
                  msg: 'Category ID not found. Please remove it.',
                  path: 'id',
                  location: 'params'
                }
            })
        }); 


        // Return 422 if category ID is invalid
          it("should return 422 if category ID is invalid", async () => {
            const invalidId = '123invalidId'; // Invalid ID format
            const updatedCategory = {
                name: 'Updated Category Name',
                image: 'http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/updated.jpg'
            };

            const response = await request(app).put(`/api/v1/categories/${invalidId}`).set('Authorization', `Bearer ${mockToken}`).send(updatedCategory);
            expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
            expect(response.body.errors).toEqual({
              id: {
                type: 'field',
                value: invalidId,
                msg: 'Invalid category ID.',
                path: 'id',
                location: 'params'
              }
            })
          });


});


//test case for get categoies for pagination
describe('GET /api/v1/categories/pagination', () => {
  const getCategoriesPaginationRoute = '/api/v1/categories/pagination';

  // Test case for 200 OK when valid pagination params are provided
  it('should return 200 OK if categories are retrieved successfully with pagination', async () => {
      const response = await request(app).get(getCategoriesPaginationRoute).query({ page: 1, limit: 10 }).set('Authorization', `Bearer ${mockToken}`);

      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body.statusCode).toBe(StatusCodes.OK);
      expect(response.body.message).toBe('All categories have been successfully retrieved.');
      expect(response.body.data.page).toBe(1);
      expect(response.body.data.per_page).toBe(10);
      expect(response.body.data.total_pages).toBe(1);
      expect(response.body.data.total_items).toBe(9);
  
      // Check that items array has the expected structure
      expect(response.body.data.items).toBeInstanceOf(Array);
      expect(response.body.data.items.length).toBeGreaterThan(0);
  
      // Optionally verify the structure of the first item only for brevity
      const category = response.body.data.items[0];
      expect(category).toMatchObject({
          _id: expect.any(String),
          name: expect.any(String),
          slug: expect.any(String),
          image: expect.any(String),
          creator_id: expect.any(String),
          updater_id: expect.any(String),
          created_at: expect.any(String),
          updated_at: expect.any(String),
          _destroy: false
      });
  
      expect(response.body.dateTime).toEqual(expect.any(String));
  });

  // Test case for 422 Bad Request if "page" is not a positive integer
  it('should return 422 Bad Request if "page" is not a positive integer', async () => {
    // Test with page as a negative integer
    let response = await request(app)
        .get(getCategoriesPaginationRoute)
        .query({ page: -1, limit: 10 })
        .set('Authorization', `Bearer ${mockToken}`);
    expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
    expect(response.body.errors).toEqual({
        page: {
            type: 'field',
            value: '-1',
            msg: 'Invalid page number.',
            path: 'page',
            location: 'query'
        }
    });
  })

  it('should return 422 Bad Request if "limit" is not a positive integer', async () => {
    // Test with page as a negative integer
    let response = await request(app)
        .get(getCategoriesPaginationRoute)
        .query({ page: 1, limit: -10 })
        .set('Authorization', `Bearer ${mockToken}`);
    expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
    expect(response.body.errors).toEqual({
        limit: {
            type: 'field',
            value: '-10',
            msg: 'Items per page are out of the valid range.',
            path: 'limit',
            location: 'query'
        }
    });
  })


  
  it('should return 200 successfully if "page" filed is not provided', async () => {
    // Test with page as a negative integer
    let response = await request(app).get(getCategoriesPaginationRoute).query({  limit: 10 }).set('Authorization', `Bearer ${mockToken}`);
 
      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body.statusCode).toBe(StatusCodes.OK);
      expect(response.body.message).toBe('All categories have been successfully retrieved.');
      expect(response.body.data.page).toBe(1);
      expect(response.body.data.per_page).toBe(10);
      expect(response.body.data.total_pages).toBe(1);
      expect(response.body.data.total_items).toBe(9);
  
      // Check that items array has the expected structure
      expect(response.body.data.items).toBeInstanceOf(Array);
      expect(response.body.data.items.length).toBeGreaterThan(0);
  
      // Optionally verify the structure of the first item only for brevity
      const category = response.body.data.items[0];
      expect(category).toMatchObject({
          _id: expect.any(String),
          name: expect.any(String),
          slug: expect.any(String),
          image: expect.any(String),
          creator_id: expect.any(String),
          updater_id: expect.any(String),
          created_at: expect.any(String),
          updated_at: expect.any(String),
          _destroy: false
    
      });
      expect(response.body.dateTime).toEqual(expect.any(String));
  })


  it('should return 200 successfully if "limit" filed is not provided', async () => {
    // Test with page as a negative integer
    let response = await request(app).get(getCategoriesPaginationRoute).query({  page: 1 }).set('Authorization', `Bearer ${mockToken}`);
 
      expect(response.status).toBe(StatusCodes.OK);
      expect(response.body.statusCode).toBe(StatusCodes.OK);
      expect(response.body.message).toBe('All categories have been successfully retrieved.');
      expect(response.body.data.page).toBe(1);
      expect(response.body.data.per_page).toBe(10);
      expect(response.body.data.total_pages).toBe(1);
      expect(response.body.data.total_items).toBe(9);
  
      // Check that items array has the expected structure
      expect(response.body.data.items).toBeInstanceOf(Array);
      expect(response.body.data.items.length).toBeGreaterThan(0);
  
      // Optionally verify the structure of the first item only for brevity
      const category = response.body.data.items[0];
      expect(category).toMatchObject({
          _id: expect.any(String),
          name: expect.any(String),
          slug: expect.any(String),
          image: expect.any(String),
          creator_id: expect.any(String),
          updater_id: expect.any(String),
          created_at: expect.any(String),
          updated_at: expect.any(String),
          _destroy: false
    
      });
      expect(response.body.dateTime).toEqual(expect.any(String));
  })


  it('should return 200 and categories sorted by _id in ascending order', async () => {
    const response = await request(app)
        .get(getCategoriesPaginationRoute)
        .query({ page: 1, limit: 10, sort_by: '_id', sort_order: 'asc' })
        .set('Authorization', `Bearer ${mockToken}`);

    expect(response.status).toBe(StatusCodes.OK);
    expect(response.body.statusCode).toBe(StatusCodes.OK);
    expect(response.body.message).toBe('All categories have been successfully retrieved.');
    expect(response.body.data.page).toBe(1);
    expect(response.body.data.per_page).toBe(10);
    expect(response.body.data.total_pages).toBeGreaterThanOrEqual(1);
    expect(response.body.data.total_items).toBeGreaterThan(0);

    // Check that items array has the expected structure and is sorted by _id in ascending order
    const items = response.body.data.items;
    expect(items).toBeInstanceOf(Array);
    expect(items.length).toBeGreaterThan(0);

    // Optionally verify the structure of the first item only for brevity
    const category = items[0];
    expect(category).toMatchObject({
        _id: expect.any(String),
        name: expect.any(String),
        slug: expect.any(String),
        image: expect.any(String),
        creator_id: expect.any(String),
        updater_id: expect.any(String),
        created_at: expect.any(String),
        updated_at: expect.any(String),
        _destroy: expect.any(Boolean)
    });

    // Verify items are sorted by _id in ascending order
    for (let i = 0; i < items.length - 1; i++) {
        expect(items[i]._id < items[i + 1]._id).toBe(true);
    }

    expect(response.body.dateTime).toEqual(expect.any(String));
});


          it('should return 200 and categories sorted by _id in descending order', async () => {
            const response = await request(app)
                .get(getCategoriesPaginationRoute)
                .query({ page: 1, limit: 10, sort_by: '_id', sort_order: 'desc' })
                .set('Authorization', `Bearer ${mockToken}`);

            expect(response.status).toBe(StatusCodes.OK);
            expect(response.body.statusCode).toBe(StatusCodes.OK);
            expect(response.body.message).toBe('All categories have been successfully retrieved.');
            expect(response.body.data.page).toBe(1);
            expect(response.body.data.per_page).toBe(10);
            expect(response.body.data.total_pages).toBeGreaterThanOrEqual(1);
            expect(response.body.data.total_items).toBeGreaterThan(0);

            // Check that items array has the expected structure and is sorted by _id in descending order
            const items = response.body.data.items;
            expect(items).toBeInstanceOf(Array);
            expect(items.length).toBeGreaterThan(0);

            // Verify the structure of the first item only for brevity
            const category = items[0];
            expect(category).toMatchObject({
                _id: expect.any(String),
                name: expect.any(String),
                slug: expect.any(String),
                image: expect.any(String),
                creator_id: expect.any(String),
                updater_id: expect.any(String),
                created_at: expect.any(String),
                updated_at: expect.any(String),
                _destroy: expect.any(Boolean)
            });

            // Verify items are sorted by _id in descending order
            for (let i = 0; i < items.length - 1; i++) {
                expect(items[i]._id > items[i + 1]._id).toBe(true);
            }

            expect(response.body.dateTime).toEqual(expect.any(String));
          });

  // Test case for 401 Unauthorized if no token is provided
  it('should return 401 Unauthorized if no token is provided', async () => {
      const response = await request(app)
          .get(getCategoriesPaginationRoute)
          .query({ page: 1, limit: 10 });

      expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(response.body).toEqual({
          message: 'You must be logged in to continue.',
          created_at: expect.any(String),
          updated_at: expect.any(String),
          messageConstants: null,
          name: 'ErrorWithStatus'
      });
  });

//   // Test case for 403 Forbidden if non-admin tries to access the route
  it('should return 403 Forbidden if non-admin tries to access the route', async () => {
      const response = await request(app)
          .get(getCategoriesPaginationRoute)
          .query({ page: 1, limit: 10 })
          .set('Authorization', `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NmUzMzBhZjYzYzI1YTRkNmI4MmQ1NzkiLCJlbWFpbCI6InBoYW1oYW5zdDRAZ21haWwuY29tIiwicm9sZSI6IlVzZXIiLCJ0b2tlbl90eXBlIjoiQWNjZXNzVG9rZW4iLCJpYXQiOjE3MzA3OTMzMjAsImV4cCI6MTczOTM0NjkyMH0.ywKFrvzZlhqeZ_DUA3A04mrfc3uwOS-qUwymXf_QOmI`); // Assuming a non-admin token

      expect(response.status).toBe(StatusCodes.FORBIDDEN);
      expect(response.body).toEqual({
          message: 'You do not have the necessary permissions for this action.',
          created_at: expect.any(String),
          updated_at: expect.any(String),
          messageConstants: null,
          name: 'ErrorWithStatus'
      });
  });

})
  

//test case for create product
// describe('POST /api/v1/products', () => {
//   let accessProductToken = '';
//   beforeAll(async () => {
//     await databaseService.connect();
//     const response = await request(app).post('/api/v1/users/login').send({ email: 'phamhanst4@gmail.com', password: '475_DienBienPhu' });
//     accessProductToken= response.body.data.access_token;
//   });

//   const createProductRoute = '/api/v1/products';
//   const createProductPayload = {
//     name: 'Organic Apples',
//     description: 'Fresh and organic apples directly from the farm.',
//     origin: 'USA',
//     supplier_id: 'supplier123',
//     category_id: 'category123',
//     images: [
//       { url: 'http://res.cloudinary.com/example/image/upload/v1234567890/photo/apple.jpg' }
//     ],
//     thumbnail_url: 'http://res.cloudinary.com/example/image/upload/v1234567890/photo/thumb_apple.jpg',
//     attributes: [
//       {
//         weight: 1.5,
//         original_price: 10,
//         discounted_percent: 15,
//         dimensions: '10x10x5 cm',
//         unit_of_measurement: 'kg',
//         quantity_per_unit: 10,
//         certification: 'Organic',
//         harvest_date: '2023-10-01',
//         link: 'http://example.com/product-detail',
//         expiration_date: '2024-10-01'
//       }
//     ]
//   };

//   // Test case for 201 Created if product is created successfully
//   it('should return 201 Created if product is created successfully', async () => {
//     const response = await request(app)
//       .post(createProductRoute)
//       .set('Authorization', `Bearer ${mockToken}`)
//       .send(createProductPayload);
//     expect(response.status).toBe(StatusCodes.CREATED);
//     expect(response.body).toEqual({
//       statusCode: StatusCodes.CREATED,
//       message: 'Product successfully inserted.',
//       data: {
//         acknowledged: true,
//         insertedId: expect.any(String)
//       },
//       dateTime: expect.any(String)
//     });
//   });

//   // Should return 401 Unauthorized if no token is provided
//   it('should return 401 Unauthorized if no token is provided', async () => {
//     const response = await request(app)
//       .post(createProductRoute)
//       .send(createProductPayload);
//     expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
//     expect(response.body).toEqual({
//       message: 'You must be logged in to continue.',
//       created_at: expect.any(String),
//       updated_at: expect.any(String),
//       messageConstants: null,
//       name: "ErrorWithStatus"
//     });
//   });

//   // Should return 401 Unauthorized if the token is invalid
//   it('should return 401 Unauthorized if the token is invalid', async () => {
//     const response = await request(app)
//       .post(createProductRoute)
//       .set('Authorization', 'Bearer invalidToken')
//       .send(createProductPayload);
//     expect(response.status).toBe(StatusCodes.UNAUTHORIZED);
//     expect(response.body).toEqual({
//       message: 'jwt malformed',
//       created_at: expect.any(String),
//       updated_at: expect.any(String),
//       messageConstants: null,
//       name: "ErrorWithStatus"
//     });
//   });

//   // Should return 403 Forbidden if the user is not an admin
//   it('should return 403 Forbidden if the user is not an admin', async () => {
//     const response = await request(app)
//       .post(createProductRoute)
//       .set('Authorization', `Bearer ${mockToken}`)
//       .send(createProductPayload);
//     expect(response.status).toBe(StatusCodes.FORBIDDEN);
//     expect(response.body).toEqual({
//       message: 'You do not have the necessary permissions for this action.',
//       created_at: expect.any(String),
//       updated_at: expect.any(String),
//       messageConstants: null,
//       name: 'ErrorWithStatus'
//     });
//   });

//   // Should return 400 Bad Request if name is missing
//   it('should return 400 Bad Request if name is missing', async () => {
//     const missingNamePayload = { ...createProductPayload, name: '' };
//     const response = await request(app)
//       .post(createProductRoute)
//       .set('Authorization', `Bearer ${mockToken}`)
//       .send(missingNamePayload);
//     expect(response.status).toBe(StatusCodes.BAD_REQUEST);
//     expect(response.body.errors).toEqual({
//       name: {
//         type: 'field',
//         value: '',
//         msg: 'Product name is required.',
//         path: 'name',
//         location: 'body'
//       }
//     });
//   });

//   // Should return 422 Unprocessable Entity if URL is invalid
//   it('should return 422 Unprocessable Entity if URL is invalid', async () => {
//     const invalidUrlPayload = {
//       ...createProductPayload,
//       images: [{ url: 'invalid-url.doc' }]
//     };
//     const response = await request(app)
//       .post(createProductRoute)
//       .set('Authorization', `Bearer ${mockToken}`)
//       .send(invalidUrlPayload);
//     expect(response.status).toBe(StatusCodes.UNPROCESSABLE_ENTITY);
//     expect(response.body.errors).toEqual({
//       images: [
//         {
//           type: 'field',
//           value: 'invalid-url.doc',
//           msg: 'Image URL must end with .jpeg, .jpg, or .png.',
//           path: 'images[0].url',
//           location: 'body'
//         }
//       ]
//     });
//   });

//   // Should return 409 Conflict if product with the same name already exists
//   it('should return 409 Conflict if product with the same name already exists', async () => {
//     const duplicateNamePayload = { ...createProductPayload, name: 'Organic Apples' };
//     const response = await request(app)
//       .post(createProductRoute)
//       .set('Authorization', `Bearer ${mockToken}`)
//       .send(duplicateNamePayload);
//     expect(response.status).toBe(StatusCodes.CONFLICT);
//     expect(response.body).toEqual({
//       statusCode: StatusCodes.CONFLICT,
//       message: 'Product name already exists. Please use a unique name.',
//       data: duplicateNamePayload.name,
//       datetime: expect.any(String)
//     });
//   });
// });

//test case for update product
// describe('GET /api/v1/products', () => {
//   let accessProductToken = '';

//   beforeAll(async () => {
//     await databaseService.connect();
//     const response = await request(app)
//       .post('/api/v1/users/login')
//       .send({ email: 'phamhanst20@gmail.com', password: '475_DienBienPhu' });
//     accessProductToken = response.body.data.access_token;
//   });

//   const getProductsRoute = '/api/v1/products';

//   it('should return 200 OK and a list of products with the expected structure', async () => {
//     const response = await request(app)
//       .get(getProductsRoute)
//       .set('Authorization', `Bearer ${accessProductToken}`);

//     expect(response.status).toBe(200);
//     expect(response.body).toMatchObject({
//       statusCode: 200,
//       message: 'All products have been successfully retrieved.',
//       data: expect.any(Array),
//       dateTime: expect.any(String),
//     });

//     // Check structure of the first product in the data array
//     const product = response.body.data[0];
//     expect(product).toMatchObject({
//       _id: expect.any(String),
//       name: expect.any(String),
//       slug: expect.any(String),
//       description: expect.any(String),
//       origin: expect.any(String),
//       sold: expect.any(Number),
//       thumbnail_url: expect.any(String),
//       images: expect.arrayContaining([
//         expect.objectContaining({
//           _id: expect.any(String),
//           url: expect.any(String),
//           created_at: expect.any(String),
//         }),
//       ]),
//       rating: expect.any(Number),
//       numberOfReview: expect.any(Number),
//       hot: expect.any(Boolean),
//       category: null,
//       hashtags: expect.any(Array),
//       supplier: expect.objectContaining({
//         _id: expect.any(String),
//         company_name: expect.any(String),
//         phone: expect.any(String),
//         email: expect.any(String),
//         contact_name: expect.any(String),
//         address: expect.any(String),
//       }),
//       attributes: expect.arrayContaining([
//         expect.objectContaining({
//           _id: expect.any(String),
//           weight: expect.any(Number),
//           original_price: expect.any(Number),
//           discounted_percent: expect.any(Number),
//           dimensions: expect.any(String),
//           unit_of_measurement: expect.any(String),
//           quantity_per_unit: expect.any(Number),
//           certification: expect.any(String),
//           harvest_date: expect.any(String),
//           link: expect.any(String),
//           expiration_date: expect.any(String),
//           product_id: expect.any(String),
//           discount_price: expect.any(Number),
//           total_price: expect.any(Number),
//         })
//       ])
//     })
  
//   })

// })


//test case for create products
describe('POST /api/v1/products', () => {

  const postProductsRoute = '/api/v1/products';
  let accessCreateProductToken = '';

  beforeAll(async () => {
    await databaseService.connect();
    const response = await request(app)
      .post('/api/v1/users/login')
      .send({ email: 'phamhanst20@gmail.com', password: '475_DienBienPhu' });
      accessCreateProductToken = response.body.data.access_token;
  });
  it('should return 201 Created and the newly created product with the expected structure', async () => {
    const newProduct = {
      name: "Dragon Fruit",
      description: "Very delicious and fresh",
      origin: "VietNam",
      supplier_id: "66990bb1b2fd0b02874e9dd7",
      category_id: "669fc663ba1ac5ace3ccdae5",
      images: [
        { url: "http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/iyxuvvoqqnhdxk8bq2va.jpg" }
      ],
      thumbnail_url: "http://res.cloudinary.com/dpbm00eke/image/upload/v1714448710/photo/iyxuvvoqqnhdxk8bq2va.jpg",
      attributes: [
        {
          weight: 0.32,
          original_price: 30000,
          discounted_percent: 10,
          dimensions: "30x20x10 cm",
          unit_of_measurement: "kg",
          quantity_per_unit: 0.32,
          certification: "USDA Organic",
          harvest_date: "2024-07-18",
          link: "https://vi.wikipedia.org/wiki/Thanh_long",
          expiration_date: "2025-08-22"
        }
      ]
    };

    const response = await request(app).post(postProductsRoute).set('Authorization', `Bearer ${accessCreateProductToken}`).send(newProduct);

    expect(response.status).toBe(StatusCodes.CREATED);
    expect(response.body).toMatchObject({
      statusCode: 201,
      message: 'Product created successfully',
      data: expect.objectContaining({
        _id: expect.any(String),
        name: newProduct.name,
        description: newProduct.description,
        origin: newProduct.origin,
        supplier_id: newProduct.supplier_id,
        category_id: newProduct.category_id,
        images: expect.arrayContaining([
          expect.objectContaining({
            _id: expect.any(String),
            url: newProduct.images[0].url,
          }),
        ]),
        thumbnail_url: newProduct.thumbnail_url,
        attributes: expect.arrayContaining([
          expect.objectContaining({
            weight: newProduct.attributes[0].weight,
            original_price: newProduct.attributes[0].original_price,
            discounted_percent: newProduct.attributes[0].discounted_percent,
            dimensions: newProduct.attributes[0].dimensions,
            unit_of_measurement: newProduct.attributes[0].unit_of_measurement,
            quantity_per_unit: newProduct.attributes[0].quantity_per_unit,
            certification: newProduct.attributes[0].certification,
            harvest_date: newProduct.attributes[0].harvest_date,
            link: newProduct.attributes[0].link,
            expiration_date: newProduct.attributes[0].expiration_date,
          }),
        ]),
      }),
    });
  });
});

    
}) 