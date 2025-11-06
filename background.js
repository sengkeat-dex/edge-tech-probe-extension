console.log('Background script loaded');

// Simple message forwarder
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('Background received message:', msg);
  
  if (msg?.type === 'PROBE_RESULT') {
    console.log('Forwarding probe result to popup');
    // Forward to popup
    chrome.runtime.sendMessage(msg)
      .then(() => console.log('Message forwarded successfully'))
      .catch(error => {
        // This is normal when popup is closed - not an error
        if (error.message.includes('Could not establish connection') || 
            error.message.includes('Receiving end does not exist')) {
          console.log('Popup not open to receive message - this is normal');
        } else {
          console.error('Unexpected error forwarding message:', error);
        }
      });
  }
  
  // Always send a response
  sendResponse({ received: true });
  return false; // Indicates sync response
});

console.log('Background script initialization complete');