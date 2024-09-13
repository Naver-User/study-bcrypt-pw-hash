package org.zerock.myapp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;


@Log4j2
@NoArgsConstructor

@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)

// BCryptPasswordEncoder 가 Main
public class BCryptPasswordEncoderTests {
	private PasswordEncoder encoder;
	
	
	@BeforeAll
	void beforeAll() {	// 1회성 전처리 수행
		log.trace("beforeAll() invoked.");
		
		// 1st. method : Helper 클래스의 메소드를 이용한 객체 생성
		PasswordEncoder encoder = 
			PasswordEncoderFactories
				.createDelegatingPasswordEncoder();
		
		// 2nd. method : 생성자를 통한 객체 생성
//		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		
		Objects.requireNonNull(encoder);
		log.info("\t+ encoder: {}", encoder);
		
		this.encoder = encoder;
	} // beforeAll
	
	
//	@Disabled
	@Order(1)
	@Test
//	@RepeatedTest(1)
	@DisplayName("1. 사용자 입력암호를 BCrypt 해쉬알고리즘으로 해쉬값 생성")
	@Timeout(1L)
	void testBCryptPasswodEncoder() {
		log.trace("testBCryptPasswodEncoder() invoked.");
		
		String password = "Yoseph1234^&";
		
		// BCrypt 라는 암호화 알고리즘은,
		// (1) 해쉬 알고리즘(알고리즘명: SHA-256)
		// (2) 알고리즘 수행결과로 나온 값 => Hash
		// (3) 불가역적인 단방향 암호화 알고리즘
		String hashValue = this.encoder.encode(password);
		log.info("\t+ hashValue: {}", hashValue);
	} // testBCryptPasswodEncoder
	
	
//	@Disabled
	@Order(2)
	@Test
//	@RepeatedTest(1)
	@DisplayName("2. 입력암호 + salt 를 BCrypt 해쉬알고리즘으로 해쉬값 생성")
	@Timeout(1L)
	void testBCryptPasswodEncoderWithSalt() {
		log.trace("testBCryptPasswodEncoderWithSalt() invoked.");
		
		String originalPassword = "Yoseph1234^&";
		
		// 주로 외부 공격자가, 해쉬알고리즘이 만들어내는 해쉬패턴을 
		// 유추하기 힘들게 하는 목적으로 소금칩니다!!
		String salt = "__SALT__";	
		
		String password = originalPassword + salt;
		
		// BCrypt 라는 암호화 알고리즘은,
		// (1) 해쉬 알고리즘(알고리즘명: SHA-256)
		// (2) 알고리즘 수행결과로 나온 값 => Hash
		// (3) 불가역적인 단방향 암호화 알고리즘
		// (4) 원래의 암호(=생선)에 소금(=salt)를 쳐서 구우자!!!
		String hashValue = this.encoder.encode(password);
		log.info("\t+ hashValue: {}", hashValue);
	} // testBCryptPasswodEncoderWithSalt
	
	
	// 테이블에 저장된 각 사용자의 암호에 대한 해쉬값(=구운생선)을 가지고
	// 사용자 로그인시에 입력된 암호(=살아있는생선)을 어떻게 비교해서
	// 같은지/다른지 검증해보자!!! (인증기법)
	
	// 살아있는 생선(암호) == 구운 생선(해쉬) ==> XX
	// BCrypt ==> De-facto Standard Hash Algorithm
	// 어떻게 비교해야 되느냐? ---> 수학적 알고리즘에 의해 검증
	
	
//	@Disabled
	@Order(3)
	@Test
//	@RepeatedTest(1)
	@DisplayName("3. 기존 저장된 해쉬값과 인증을 위해 입력된 암호가 같은지 검증")
	@Timeout(value=1L, unit=TimeUnit.MINUTES)
	void testPasswordMatching() {
		log.trace("testPasswordMatching() invoked.");
		
		// 테이블에 저장된 해쉬값과 인증을 위해 입력된 암호의 검증
		String password = "Yoseph1234^&";
		
		// Case1 - 단 한번만 해싱 수행해서, 검증
		String hash = this.encoder.encode(password);
		
		// 만약에 사용자가 암호를 잘못입력햇다면...
//		password = password + '?';
		
		boolean isMatched = this.encoder.matches(password, hash);
		
		assertEquals(true, isMatched);	// 두 값이 똑같다!(true)
		
		// Case2 - 지정된 횟수만큼, 해쉬를 수행해서, 매번 다르게 나오는 해쉬값으로
		//		   입력된 암호와 같은지/다른지 검증해보자!!!
		for(int i=0; i< 100; i++) {
			// (1) 매번 달라지는 해쉬값 생성
			hash = this.encoder.encode(password);
			
			// (2) 위 (1)의 해쉬값으로도 계속 매칭이 가능할까!???
			isMatched = this.encoder.matches(password, hash);
			
			assertEquals(true, isMatched);	// 두 값이 똑같다!(true)
		} // for
		
		log.info("Done.");
	} // testPasswordMatching	
	
	
//	@Disabled
	@Order(4)
	@Test
//	@RepeatedTest(1)
	@DisplayName("4. 같은 암호에 대해서, 2개의 해쉬를 생성하고, 각각 해쉬와 암호를 비교")
	@Timeout(value=1L, unit=TimeUnit.MINUTES)
	void testPasswordMatchingWithTwoHash() {
		log.trace("testPasswordMatchingWithTwoHash() invoked.");
		
		String originalPassword = "1234567890ABCD^&%";
		String salt = "__SALT__";
		
		String password = originalPassword + salt;
		
		// SALT가 추가된 암호에 대해서, 해쉬 2번 추출
		String hash1 = this.encoder.encode(password);
		String hash2 = this.encoder.encode(password);
		
		log.info("AreHashesEqual? {}", (hash1 == hash2));
		
		// 각각의 해쉬값에 대하여, 동일한 원래 암호에 대해서 매칭시켜보자!
		boolean match1 = this.encoder.matches(password, hash1);
		boolean match2 = this.encoder.matches(password, hash2);
		
		assertEquals(true, (match1 == match2));
	} // testPasswordMatchingWithTwoHash
	
	
	
	
	
	
	
	
	
	
	

} // end class
