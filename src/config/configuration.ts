let AWS = require('aws-sdk')

export default () => ({
	port: parseInt(process.env.ICO_PORT, 10) || 4000,
	database_url: process.env.ICO_DATABASE_URL,
	main_url: process.env.ICO_MAIN_URL,
	aws_s3_bucket_name : process.env.ICO_AWS_BUCKT_KEY,
	jwt_secret : process.env.ICO_JWT_SECRET,
	coingate_token : process.env.ICO_COINGATE_TOKEN,
	receiver_address: process.env.ICO_RECEIVER_ADDRESS,
	s3: new AWS.S3({
		accessKeyId : process.env.ICO_AWS_S3_ACCESS_KEY_ID,
		secretAccessKey : process.env.ICO_AWS_S3_SECRET_ACCESS_KEY,
		signatureVersion: process.env.ICO_AWS_S3_SIGNATURE_VERSION,
	})
  });