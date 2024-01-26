//
//  ViewController.m
//  1111111
//
//  Created by Mac on 2024/1/25.
//

#import "ViewController.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSData *data = [ViewController aes128_encryptWithData:[@"12345678" dataUsingEncoding:NSUTF8StringEncoding] key:@"3mxTAiHP4cbi3Ij5u8hs3M" iv:@"1111111111111111"];
    NSLog(@"新的data:%@",data);
    
    NSString *string = [ViewController aes128_decryptH16WithEnStr:data  key:@"3mxTAiHP4cbi3Ij5u8hs3M" iv:@"1111111111111111"];
    NSLog(@"新的data 解密:%@", string);
}


+ (NSData *)aes128_encryptWithData:(NSData *)data key:(NSString *)key iv:(NSString *)iv { //加密
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivData.bytes,
                                          [data bytes],
                                          dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *result = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        return result;
    }
    free(buffer);
    return nil;
}


+ (NSString *)aes128_decryptH16WithEnStr:(NSData *)data key:(NSString *)key iv:(NSString *)iv {
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
    NSData *decodeData = data;
    //对数据进行解密
    NSData *result = nil;
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [decodeData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          ivData.bytes,
                                          [decodeData bytes],
                                          dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    
    if (result && result.length > 0) {
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    
    free(buffer);
    return nil;
}


@end
