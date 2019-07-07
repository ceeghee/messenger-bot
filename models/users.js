 const mongoose     = require('mongoose');
 const Schema       = mongoose.Schema;


 const UsersSchema = new Schema({
 	userId:{ type:String, unique:true, required:true},
 	messages: { type:Array }
 })



  module.exports = mongoose.model('User', UsersSchema); 