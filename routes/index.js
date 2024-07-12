import authRoute from './auth.route.js'

export default (app) => {
  app.use('/api/v1/auth',authRoute)
}