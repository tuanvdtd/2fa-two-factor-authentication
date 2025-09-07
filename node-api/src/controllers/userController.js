import { StatusCodes } from 'http-status-codes'
import { pickUser } from '~/utils/formatters'
import { authenticator } from 'otplib'
import qrcode from 'qrcode'

// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này sử dụng nedb-promises để lưu và truy cập dữ liệu từ một file JSON. Coi như file JSON này là Database của dự án.
const Datastore = require('nedb-promises')
const UserDB = Datastore.create('src/database/users.json')
const twoFactorSecretKeyDB = Datastore.create('src/database/2fa_secret_keys.json')
const userSessionDB = Datastore.create('src/database/user_sessions.json')

const serviceName = '2FA-Demo (Dev)'

const login = async (req, res) => {
  try {
    const user = await UserDB.findOne({ email: req.body.email })
    // Không tồn tại user
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // Kiểm tra mật khẩu "đơn giản". LƯU Ý: Thực tế phải dùng bcryptjs để hash mật khẩu, đảm bảo mật khẩu được bảo mật. Ở đây chúng ta làm nhanh gọn theo kiểu so sánh string để tập trung vào nội dung chính là 2FA.
    if (user.password !== req.body.password) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Wrong password!' })
      return
    }

    res.status(StatusCodes.OK).json(pickUser(user))
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const getUser = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    res.status(StatusCodes.OK).json(pickUser(user))
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Xóa phiên của user trong Database > user_sessions tại đây khi đăng xuất

    res.status(StatusCodes.OK).json({ loggedOut: true })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const get2FA_QRCode = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Biến lưu trữ 2fa secret key của user trong Database > 2fa_secret_keys tại đây
    let twoFactorSecretKeyValue = null
    const twoFactorSecretKey = await twoFactorSecretKeyDB.findOne({ user_id: user._id })
    if (!twoFactorSecretKey) {
      // tạo mới 2fa secret key cho user bằng thư viện otplib
      const twoNewFactorSecretKey = await twoFactorSecretKeyDB.insert({ user_id: user._id, value: authenticator.generateSecret() })
      twoFactorSecretKeyValue = twoNewFactorSecretKey.value
    }
    else {
      twoFactorSecretKeyValue = twoFactorSecretKey.value
    }

    // Tạo OTP token
    const otpAuthToken = authenticator.keyuri(user.email, serviceName, twoFactorSecretKeyValue)
    // Tạo QR code từ OTP token trên
    const qrCodeImageUrl = await qrcode.toDataURL(otpAuthToken)

    res.status(StatusCodes.OK).json({ qrcode: qrCodeImageUrl })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const setup2FA = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Biến lưu trữ 2fa secret key của user trong Database > 2fa_secret_keys tại đây
    const twoFactorSecretKey = await twoFactorSecretKeyDB.findOne({ user_id: user._id })
    if (!twoFactorSecretKey) {
      res.status(StatusCodes.NOT_FOUND).json({ message: '2FA secret key not found!' })
      return
    }
    const twoFactorSecretKeyValue = twoFactorSecretKey.value
    const otpTokenFromClient = req.body.otpToken
    if (!otpTokenFromClient) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'OTP token is required!' })
      return
    }

    // Xác thực OTP token từ phía client gửi lên
    const isValid = authenticator.verify({ token: otpTokenFromClient, secret: twoFactorSecretKeyValue })
    if (!isValid) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Invalid OTP token!' })
      return
    }

    // Cập nhật trạng thái đã bật 2FA cho user trong Database > users tại đây
    const updatedUser = await UserDB.update(
      { _id: user._id },
      { $set: { require_2fa: true } },
      { returnUpdatedDocs: true }
    )
    UserDB.compactDatafileAsync() // Giải phóng dung lượng file database

    const newUserSession = await userSessionDB.insert(
      {
        user_id: user._id,
        device_id: `${req.headers['user-agent']}-${new Date().valueOf()}`, // device_id tạm thời lấy user-agent + timestamp để tạm đại diện cho một thiết bị
        is_2fa_verified: true,
        last_login: new Date().valueOf()
      }
    ) // Tạo phiên đã xác thực 2FA cho user trong Database > user_sessions tại đây

    // Trả về thông tin user đã được cập nhật
    res.status(StatusCodes.OK).json(
      {
        ...pickUser(updatedUser),
        is_2fa_verified: newUserSession.is_2fa_verified,
        last_login: newUserSession.last_login
      })

  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const userController = {
  login,
  getUser,
  logout,
  get2FA_QRCode,
  setup2FA
}
