const Joi = require('joi')

const username = Joi.string().trim().lowercase()
  .min(3).message('Username should contain at least 3 characters')
  .max(30).message('Username length can not be more than 30')
  .messages({
    'string.empty': 'Username can not be empty',
    'string.min': 'Username should contain at least 3 characters',
    'string.max': 'Username length can not be more than 30 characters'
  })


const password = Joi.string().trim()
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{16,32}$/)
  .messages({
    'string.empty': 'Password can not be empty',
    'string.pattern.base': 'Password should contain at least 1 uppercase, 1 lowercase letter, 1 number and 1 special character and be between 16 and 32 in length'
  })

const email = Joi.string().trim().lowercase()
  .email({ minDomainSegments: 2, tlds: { allow: ['com', 'tech'] } })
  .messages({
    'string.empty': 'Email can not be empty',
    'string.email': 'Allowed email domains: com - tech'
  })

const department = Joi.string().trim().lowercase()
  .min(2)
  .max(30)
  .messages({
    'string.empty': 'Department can not be empty',
    'string.min': 'Department should contain at least 2 characters',
    'string.max': 'Department length can not be more than 30 characters'
  })

const validators = {
  username,
  password,
  email,
  department,
}

module.exports = validators
