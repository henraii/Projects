import type { APIRoute } from 'astro';
import { connectToMongo } from '../../lib/mongodb';
import jwt from 'jsonwebtoken';

export const GET: APIRoute = async () => {
  try {
    const db = await connectToMongo();
    const posts = await db.collection('posts').find().sort({ created_at: -1 }).toArray();
    return new Response(JSON.stringify(posts), { status: 200 });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Server error' }), { status: 500 });
  }
};

export const POST: APIRoute = async ({ request }) => {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, import.meta.env.JWT_SECRET) as { userId: string };
    const { title, content } = await request.json();

    const db = await connectToMongo();
    const post = {
      title,
      content,
      user_id: decoded.userId,
      created_at: new Date(),
    };
    await db.collection('posts').insertOne(post);
    return new Response(JSON.stringify({ message: 'Post created' }), { status: 201 });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Server error' }), { status: 500 });
  }
};