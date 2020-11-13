import { KJUR, hextob64 ,KEYUTIL} from "jsrsasign";

import * as _ from 'lodash';
import axios from "axios";

/**
 * @param app_id 应用ID
 * @param method 接口方法
 * @param format 格式
 * @param charset 字符
 * @param sign_type 签名类型 SHA256withRSA 或 SHA1withRSA
 * @param timestamp 当前时间 格式为 2020-11-11 11:11:11
 * @param version 版本号 默认为 “1.0”
 * @param biz_content 业务参数内容 默认值为{}
 */
interface SignContentParams {
  app_id: string;
  method: string;
  format: string;
  charset: string;
  sign_type: string;
  timestamp: string;
  version: string; // 1.0
  biz_content: string;
}

class ZxSop {
  private appId: string;
  private appKey: string;
  private baseApiUri: string = "http://192.168.0.61:8152";

  // private HashMap:Object = {
  //   SHA256withRSA: "SHA256withRSA",
  //   SHA1withRSA: "SHA1withRSA",
  // };

  private PEM_BEGIN: string = "-----BEGIN PRIVATE KEY-----\n";
  private PEM_END: string = "\n-----END PRIVATE KEY-----";

  public constructor(appId: string, appKey: string) {
    this.appId = appId;
    this.appKey = appKey;
  }

  /**
   * rsa签名
   * 
   * @param content 签名内容
   * @param hash hash算法，SHA256withRSA | SHA1withRSA
   * @return Base64URL encoded string 返回签名字符串
   */
  private rsaSign(content: string, hash: string):string {
    // 1.创建 Signature 对象
    const signature = new KJUR.crypto.Signature({
      alg: hash
    });
    const privateKey: string = this.formatKey();
    // 2.初始化 key
    const key = KEYUTIL.getKey(privateKey);
    signature.init(key);
    // 3. 设置签名内容 
    signature.updateString(content);
    // 4. 签名
    const signData = signature.sign();
    // 5. 签名转成 Base64URL encoded 字符串
    return hextob64(signData);
  }
  /***
   * 格式化 appKey 
   */
  private formatKey(): string {
    // console.info('ddd',_.startsWith(PEM_BEGIN,key));
    let currentAppkey: string = this.appKey;
    if (!_.startsWith(currentAppkey, this.PEM_BEGIN)) {
      currentAppkey = this.PEM_BEGIN + currentAppkey;
    }
    if (!_.endsWith(currentAppkey, this.PEM_END)) {
      currentAppkey = currentAppkey + this.PEM_END;
    }
    console.info("currentAppkey", currentAppkey);
    return currentAppkey;
  }

  private signature(content: string, signType: string) {
    if (signType.toUpperCase() === "RSA2") {
      return this.rsaSign(content, "SHA256withRSA");
    } else if (signType.toUpperCase() === "RSA") {
      return this.rsaSign(content, "SHA1withRSA");
    } else {
      console.info("签名错误");
      return false;
    }
  }

  private getSignContent(params: SignContentParams) {
    const paramNames = [];
    for (const key in params) {
      paramNames.push(key);
      if (Object.prototype.toString.call(params[key]) === "[object Object]") {
        for (const k in params[key]) {
          paramNames.push(k + "." + key);
        }
      }
    }
    paramNames.sort();
    const paramNameValue = [];

    for (let i = 0, len = paramNames.length; i < len; i++) {
      let paramName = paramNames[i];
      const paramNameArr = paramName.split(".");
      //   console.info('arr',paramNameArr);
      let val = params[paramName];
      if (paramNameArr.length === 2) {
        paramName = paramNameArr[0];
        val = params[paramNameArr[1]][paramNameArr[0]];
      }

      console.info(paramName, val);
      if (
        paramName &&
        val &&
        Object.prototype.toString.call(val) !== "[object Object]"
      ) {
        paramNameValue.push(`${paramName}=${val}`);
      }
    }
    return paramNameValue.join("&");
  }

  /**
   * 对日期进行格式化， 和C#大致一致 默认yyyy-MM-dd HH:mm:ss
   * 可不带参数 一个日期参数 或一个格式化参数
   * @param date 要格式化的日期
   * @param format 进行格式化的模式字符串
   *     支持的模式字母有：
   *     y:年,
   *     M:年中的月份(1-12),
   *     d:月份中的天(1-31),
   *     H:小时(0-23),
   *     h:小时(0-11),
   *     m:分(0-59),
   *     s:秒(0-59),
   *     f:毫秒(0-999),
   *     q:季度(1-4)
   * @return String
   * @author adswads@gmail.com
   */
  public dateFormat(date?: any, format?: string): string {
    //无参数
    if (date == undefined && format == undefined) {
      date = new Date();
      format = "yyyy-MM-dd HH:mm:ss";
    }
    //无日期
    else if (typeof date == "string") {
      format = date;
      date = new Date();
    }
    //无格式化参数
    else if (format === undefined) {
      format = "yyyy-MM-dd HH:mm:ss";
    } else {
    }
    //没有分隔符的特殊处理

    var map = {
      y: date.getFullYear() + "", //年份
      M: date.getMonth() + 1 + "", //月份
      d: date.getDate() + "", //日
      H: date.getHours(), //小时 24
      m: date.getMinutes() + "", //分
      s: date.getSeconds() + "", //秒
      q: Math.floor((date.getMonth() + 3) / 3) + "", //季度
      f: date.getMilliseconds() + "", //毫秒
    };
    //小时 12
    if (map["H"] > 12) {
      map["h"] = map["H"] - 12 + "";
    } else {
      map["h"] = map["H"] + "";
    }
    map["H"] += "";

    var reg = "yMdHhmsqf";
    var all = "",
      str = "";
    for (var i = 0, n = 0; i < reg.length; i++) {
      n = format.indexOf(reg[i]);
      if (n < 0) {
        continue;
      }
      all = "";
      for (; n < format.length; n++) {
        if (format[n] != reg[i]) {
          break;
        }
        all += reg[i];
      }
      if (all.length > 0) {
        if (all.length == map[reg[i]].length) {
          str = map[reg[i]];
        } else if (all.length > map[reg[i]].length) {
          if (reg[i] == "f") {
            str =
              map[reg[i]] +
              this.charString("0", all.length - map[reg[i]].length);
          } else {
            str =
              this.charString("0", all.length - map[reg[i]].length) +
              map[reg[i]];
          }
        } else {
          switch (reg[i]) {
            case "y":
              str = map[reg[i]].substr(map[reg[i]].length - all.length);
              break;
            case "f":
              str = map[reg[i]].substr(0, all.length);
              break;
            default:
              str = map[reg[i]];
              break;
          }
        }
        format = format.replace(all, str);
      }
    }
    return format;
  }

  /**
   * 返回字符串 为n个char构成
   * @param char 重复的字符
   * @param count 次数
   * @return String
   * @author adswads@gmail.com
   */
  public charString(char: string, count: number): string {
    var str: string = "";
    while (count--) {
      str += char;
    }
    return str;
  }

  /**
   * 
   * @param method 业务方法  SignContentParams.method eg. map.download
   * @param suffix 
   */
  public getResponseDataKey(method:string,suffix:string = '_response'):string {

    const responseDataKey = method.replace(/\./g, "_") + "_response";
    return responseDataKey;
  }

  /**
   * 下载地图
   * @param args 
   * @param version 默认 "1.0" 
   */
  public downloadMap(args: {}, version: string = "1.0") {
    version = version || "1.0";

    let requestData = {
      app_id: this.appId,
      method: "map.download",
      format: "json",
      charset: "UTF-8",
      sign_type: "RSA2",
      timestamp: this.dateFormat(new Date(), "yyyy-MM-dd HH:mm:ss"),
      version: version, // 1.0
      biz_content: JSON.stringify(args)
    };

    let signContent = this.getSignContent(requestData);
    //   signContent()
    let sign = this.signature(signContent, requestData.sign_type);

    requestData["sign"] = sign;
    // requestData.sign = sign;

    return axios(this.baseApiUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      responseType: "blob",
      data: requestData,
    }).then((response: any) => {
      console.log("ZxSop -> downloadMap -> response", response)
      if(response.status === 200) {
        return response.data;
      } else {
        return {
          status:500,
          message:'错误'
        };
      }
      // const responseDataKey = this.getResponseDataKey(requestData.method);
      // console.log("ZxSop -> downloadMap -> responseDataKey", responseDataKey);
      // return response.data;
    });
  }
  /**
   * 获取微信授权 获取微信临时票据
   * @param args 
   */
  public mpOfficialAuth(args: {}, version: string = "1.0") {
   
    let requestData = {
      app_id: this.appId,
      method: "official.auth.get",
      format: "json",
      charset: "UTF-8",
      sign_type: "RSA2",
      timestamp: this.dateFormat(new Date(), "yyyy-MM-dd HH:mm:ss"),
      version: version, // 1.0
      biz_content: JSON.stringify(args)
    };

    let signContent = this.getSignContent(requestData);
    //   signContent()
    let sign = this.signature(signContent, requestData.sign_type);

    requestData["sign"] = sign;
    // requestData.sign = sign;

    return axios(this.baseApiUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      data: requestData,
    }).then((response: any) => {
      
      const responseDataKey = this.getResponseDataKey(requestData.method);
      console.log("ZxSop -> mpOfficial -> response", response.data[responseDataKey]);
      // console.log("ZxSop -> downloadMap -> responseDataKey", responseDataKey);
      // return response.data;
      return response.data[responseDataKey];
    });
  }

  public mpOfficialTicket(args: {}, version: string = "1.0") {
   
    let requestData = {
      app_id: this.appId,
      method: "official.auth.ticket",
      format: "json",
      charset: "UTF-8",
      sign_type: "RSA2",
      timestamp: this.dateFormat(new Date(), "yyyy-MM-dd HH:mm:ss"),
      version: version, // 1.0
      biz_content: JSON.stringify(args)
    };

    let signContent = this.getSignContent(requestData);
    let sign = this.signature(signContent, requestData.sign_type);

    requestData["sign"] = sign;

    return axios(this.baseApiUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      data: requestData,
    }).then((response: any) => {
      
      const responseDataKey = this.getResponseDataKey(requestData.method);
      console.log("ZxSop -> mpOfficialTicket -> response", response.data[responseDataKey]);
      // console.log("ZxSop -> downloadMap -> responseDataKey", responseDataKey);
      // return response.data;
      return response.data[responseDataKey];
    });
  }

  // 

  /**
   * 获取 商户地图
   * @param args 
   * @param version 
   */
  public mapList(args: {}, version: string = "1.0") {
   
    let requestData = {
      app_id: this.appId,
      method: "map.list",
      format: "json",
      charset: "UTF-8",
      sign_type: "RSA2",
      timestamp: this.dateFormat(new Date(), "yyyy-MM-dd HH:mm:ss"),
      version: version, // 1.0
      biz_content: JSON.stringify(args)
    };

    let signContent = this.getSignContent(requestData);
    let sign = this.signature(signContent, requestData.sign_type);

    requestData["sign"] = sign;

    return axios(this.baseApiUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      data: requestData,
    }).then((response: any) => {
      
      const responseDataKey = this.getResponseDataKey(requestData.method);
      console.log("ZxSop -> mpOfficialTicket -> response", response.data[responseDataKey]);
      // console.log("ZxSop -> downloadMap -> responseDataKey", responseDataKey);
      return response.data[responseDataKey];
    });
  }

   /**
   * 获取附近地图
   * @param args 
   * @param version 
   */
  public mapNearest(args: {}, version: string = "1.0") {
   
    let requestData = {
      app_id: this.appId,
      method: "map.nearest.get",
      format: "json",
      charset: "UTF-8",
      sign_type: "RSA2",
      timestamp: this.dateFormat(new Date(), "yyyy-MM-dd HH:mm:ss"),
      version: version, // 1.0
      biz_content: JSON.stringify(args)
    };

    let signContent = this.getSignContent(requestData);
    let sign = this.signature(signContent, requestData.sign_type);

    requestData["sign"] = sign;

    return axios(this.baseApiUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      data: requestData,
    }).then((response: any) => {
      
      const responseDataKey = this.getResponseDataKey(requestData.method);
      console.log("ZxSop -> mapNearest -> response", response.data[responseDataKey]);
      // console.log("ZxSop -> downloadMap -> responseDataKey", responseDataKey);
      // return response.data;
      return response.data[responseDataKey];
    });
  }


  /**
   * 上传用户位置信息
   * @param args 
   * @param version 
   */
  public mapLocationUpload(args: {}, version: string = "1.0") {
   
    let requestData = {
      app_id: this.appId,
      method: "map.location.upload",
      format: "json",
      charset: "UTF-8",
      sign_type: "RSA2",
      timestamp: this.dateFormat(new Date(), "yyyy-MM-dd HH:mm:ss"),
      version: version, // 1.0
      biz_content: JSON.stringify(args)
    };

    let signContent = this.getSignContent(requestData);
    let sign = this.signature(signContent, requestData.sign_type);

    requestData["sign"] = sign;

    return axios(this.baseApiUri, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      data: requestData,
    }).then((response: any) => {
      
      const responseDataKey = this.getResponseDataKey(requestData.method);
      console.log("ZxSop -> mapLocationUpload -> response", response.data[responseDataKey]);
      // console.log("ZxSop -> downloadMap -> responseDataKey", responseDataKey);
      // return response.data;
      return response.data[responseDataKey];
    });
  }

  public getApp() {
    return {
      appId: this.appId,
      appKey: this.appKey,
    };
  }
}

if (typeof window !== "undefined") {
  // window.ZxSop = ZxSop;
  (window as any).ZxSop = ZxSop;
}

export default ZxSop;
