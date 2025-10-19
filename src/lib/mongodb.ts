// src/lib/mongodb.ts
import { MongoClient } from 'mongodb';

const uri = import.meta.env.MONGODB_URI;
const client = new MongoClient(uri);

export async function connectToMongo() {
  try {
    await client.connect();
    return client.db('myBlog');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
}