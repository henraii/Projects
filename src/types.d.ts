// src/types.d.ts

// Window extensions
interface Window {
  openChat: (chatId: any, recipientId: any) => void;
  likePost: (postId: any) => void;
}

// Global declarations
declare const io: any;
declare function openChat(chatId: any, recipientId: any): void;
declare function likePost(postId: any): void;