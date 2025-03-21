import { initializeApp } from "firebase/app";
import { getDatabase } from "firebase/database";

export const firebaseMessages = {
  ICO_TRANSACTIONS: "ico/ico_transactions/"
}

export const firebaseConfig = {
  apiKey: "AIzaSyDhSv-NY3Wm4pMlD3vdd9CFsE47gnE26nI",
  authDomain: "middnapptest.firebaseapp.com",
  databaseURL: "https://middnapptest-default-rtdb.firebaseio.com",
  projectId: "middnapptest",
  storageBucket: "middnapptest.appspot.com",
  messagingSenderId: "421259474739",
  appId: "1:421259474739:web:7ab5ac0398db5b724d3046",
  measurementId: "G-5D177SQHK8"
};
export const app = initializeApp(firebaseConfig);
export const database = getDatabase(app);
