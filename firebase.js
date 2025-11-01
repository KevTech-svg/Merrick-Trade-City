// firebase.js (v9 modular)
import { initializeApp } from "https://www.gstatic.com/firebasejs/9.24.0/firebase-app.js";
import {
  getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword,
  signOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/9.24.0/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, collection, addDoc, getDocs, query, orderBy, serverTimestamp
} from "https://www.gstatic.com/firebasejs/9.24.0/firebase-firestore.js";
import {
  getStorage, ref as storageRef, uploadBytesResumable, getDownloadURL
} from "https://www.gstatic.com/firebasejs/9.24.0/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyDD9yIS1kYVNJhVntodAUeeMAUOOtXwGdU",
  authDomain: "merrick-trade-city.firebaseapp.com",
  projectId: "merrick-trade-city",
  storageBucket: "merrick-trade-city.firebasestorage.app",
  messagingSenderId: "769684454569",
  appId: "1:769684454569:web:5f9ccf6629a0ea0db17db8"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const storage = getStorage(app);

export {
  app, auth, db, storage,
  signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, onAuthStateChanged,
  doc, getDoc, setDoc, collection, addDoc, getDocs, query, orderBy, serverTimestamp,
  storageRef, uploadBytesResumable, getDownloadURL
};