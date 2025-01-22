---
title: Cilium으로 구현하는 FQDN 기반 Kubernetes 네트워크 정책
author: kimmap
date: 2025-01-21 03:21:00 +0800
categories: [DevOps]
tags: [k8s, cilium, ebpf]
---
# 개요

클라우드 네이티브 환경에서 네트워크 트래픽 제어는 보안과 성능 관리의 핵심 과제입니다. 특히 Kubernetes에서 외부와의 egress 트래픽을 제어하려면 **FQDN(Fully Qualified Domain Name) 기반 필터링**이 중요합니다. 하지만 kubernetes의 NetworkPolicy 컨셉은 IP 주소 기반으로 동작하며, 동적으로 변경되는 도메인 이름을 효과적으로 처리하지 못하는 한계가 있습니다.

이 글에서는 **Cilium**을 사용한 방법을 중심으로, Kubernetes 환경에서 FQDN 필터링 기반 네트워크 보안을 구현하는 방법과 그 동작 원리를 설명합니다.

---

# Kubernetes NetworkPolicy의 한계

Kubernetes는Pod 간 또는 외부와의 트래픽을 제어할 수 있는 NetworkPolicy 컨셉을 제공합니다.  그러나 이는 FQDN 기반의 세밀한 필터링을 지원하지 않는다는 한계를 가지고 있습니다. 특히, 외부 도메인의 IP 주소가 동적으로 변경되는 경우 NetworkPolicy는 이를 적절히 처리할 수 없습니다.

> 💡 **Note**  
> NetworkPolicy 기능 구현은 CNI 플러그인이 담당합니다.   
> 만약 선택된 CNI가 NetworkPolicy를 지원하지 않으면 정책은 무시됩니다. 반대로, CNI에 따라 kubernetes 기본 NetworkPolicy 정의보다 더 강력한 네트워크 정책을 제공할 수도 있습니다.

### **IP 주소의 동적 변경 문제**

외부 도메인은 서비스 제공자의 **로드 밸런싱 정책**이나 **CDN**으로 인해 IP 주소가 자주 변경됩니다.

예를 들어, `google.com`의 DNS 결과는 요청마다 다를 수 있습니다:

```bash
dig +short google.com
142.250.206.238
172.217.161.238
172.217.25.174
```

NetworkPolicy로 `google.com`으로의 트래픽을 허용하려면 반환된 IP 주소를 규칙에 추가해야 합니다:

```yaml
egress:
  - to:
      - ipBlock:
          cidr: 142.250.206.238/32
      - ipBlock:
          cidr: 172.217.161.238/32
      - ipBlock:
          cidr: 172.217.25.174/32

```

NetworkPolicy에 도메인의 모든 IP를 등록하더라도, **외부 서비스의 IP가 변경**되면 정책을 수동으로 업데이트해야 합니다. 이는 트래픽이 차단되거나 예기치 않은 동작이 발생할 수 있습니다.

이 문제를 해결하려면 **FQDN 기반 필터링**이 필수적입니다. FQDN 방식은 도메인 이름을 기준으로 트래픽을 제어하므로, IP 주소의 변경에 영향을 받지 않습니다.

---

# Cilium을 통한 FQDN 필터링

### Cilium이란?

[Cilium](https://github.com/cilium/cilium?tab=readme-ov-file)은 [eBPF](https://ebpf.io/) 기술을 활용하여 Kubernetes 환경에서 고급 네트워킹과 보안 기능을 제공하는 오픈 소스 프로젝트입니다. 

Cilium CNI는 Kubernetes의 CNI 표준을 완벽히 지원하며 2023년에 [CNCF의 졸업 프로젝트](https://www.cncf.io/announcements/2023/10/11/cloud-native-computing-foundation-announces-cilium-graduation/)로 인정받아 신뢰성과 성숙도를 입증했습니다. 

여러 클라우드 네이티브 공급사에서도 Cilium 기반 CNI를  지원합니다.  Azure AKS에서는 [Cilium 기반의 CNI를 공식 지원](https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium)하며, [Network Policy 엔진으로 Cilium 사용을 권장](https://learn.microsoft.com/en-us/azure/aks/use-network-policies?source=recommendations#network-policy-options-in-aks)합니다.

### CiliumNetworkPolicy를 활용한 FQDN 필터링:

Cilium CNI는 Kubernetes의 NetworkPolicy를 확장하여 고급 네트워크 정책 기능을 제공합니다.  이를 통해 DNS 요청을 분석하고, FQDN과 IP 매핑을 관리하여 세밀한 아웃바운드 트래픽 제어가 가능합니다.

아래 정책은 demo-app 라벨링이 있는 Pod의 egress 트래픽을 제어합니다.

- kube-dns를 통한 DNS요청을 허용하고,
- [google.com](http://google.com) 으로의 HTTPS(443포트) 트래픽만 허용합니다. 


이를 통해 FQDN 기반 네트워크 정책을 적용할 수 있습니다.

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: demo-policy
spec:
  endpointSelector:
    matchLabels:
      app: demo-app
  egress:
    - toEndpoints:
      - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s:k8s-app: kube-dns
	    toPorts:
        - ports:
          - port: "53"
            protocol: ANY
          rules:
            dns:
              - matchName: "google.com"

    - toFQDNs:
      - matchName: "google.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

> 💡 **Note**  
> FQDN 필터링은 아웃바운드 트래픽 중 DNS쿼리 요청을 가로채고, 응답에서 확인된 IP 주소를 기록합니다.   
> 이 '가로채기'는 자체적으로 DNS요청을 제어하는 별도의 정책 규칙에 의해 수행되며, 위 예제의 kube-dns egress 정책 처럼 반드시 별도로 지정해야 합니다.

### FQDN 필터링의 구성 요소

- **Cilium Agent:**
    
    클러스터 내에서 DaemonSet으로 실행되는  Cilium CNI의 핵심 네트워킹 구성 요소입니다. 이는 클러스터 내의 Pod에 대해 네트워킹, 로드 밸런싱 및 네트워크 정책을 관리합니다. FQDN 정책이 적용된 Pod의 경우, Cilium Agent는 패킷을 DNS proxy로 리디렉션하여 DNS 해석을 수행하며, DNS Proxy에서 획득한 FQDN-IP 매핑 정보를 사용하여 네트워크 정책을 업데이트 합니다.
    
- **DNS Proxy:**
    
    Cilium Agent Pod 내에서, 또는 별도의 DaemonSet으로 실행될 수 있습니다. 이 에이전트는 Pod의 DNS 해석을 수행하며, 성공적으로 DNS 해석이 완료되면 Cilium 에이전트에 FQDN과 IP 매핑 정보를 업데이트합니다.
    

### **FQDN 필터링이 작동하는 방식**
![How FQDN filtering works](/assets/img/posts/2025-01-21-Cilium으로%20구현하는%20FQDN%20기반%20Kubernetes%20네트워크%20정책/how-fqdn-filtering-works.png)
_FQDN 필터링의 동작 방식 (출처: [What is Container Network Security?](https://learn.microsoft.com/en-us/azure/aks/container-network-security-concepts#how-fqdn-filtering-works/))_

1. Pod에서 [google.com](http://google.com) url에 대한 아웃바운드 트래픽이 발생합니다. 
2. Cilium Agent는 Pod에서 발생하는 DNS 쿼리를 가로채고, 정책에 따라 패킷을 DNS Proxy로 리디렉션 합니다. (Cilium Agent는 eBPF를 이용해 패킷을 식별 및 리디렉션 합니다)
3. DNS Proxy는 L7 정책 기준에 따라 [google.com](http://google.com)의 egress를 허용할지 결정합니다.
4. DNS요청을 DNS 서버 - 보통의 경우 coreDNS - 로 forward 합니다.
5. DNS 서버의 응답에서 확인되는 google.com 대한 IP 주소를 확인합니다.
6.  DNS Proxy는 [google.com](http://google.com) 의 IP 주소로 Cilium Agent의 FQDN 매핑 정보를 업데이트 합니다. 

이 과정을 통해 Cilium Agent는 정책 엔진 내에서 도메인에 대한 IP주소 정보를 캐싱하고 L3/L4 기반의 정책을 업데이트 할 수 있습니다.  이후에 동일한 [google.com](http://google.com) 아웃바운드 트래픽이 발생할 때는 eBPF 프로그램을 통해 커널 레벨에서 정책 기반 필터링이 수행됩니다.

# Cilium과 eBPF

이전 섹션에서 Cilium Agent가 Pod에서 발생하는 아웃바운드 패킷을 '가로채고' '리디렉션' 하는것을 확인했습니다. 그런데, 이런것이 어떻게 가능한 걸까요? Cilium은 eBPF 커널 기술을 통해 이러한 기능을 수행합니다.

### **eBPF란?**

eBPF는 개발자가 작성한 코드를 커널에 동적으로 로드하고 커널의 동작 방식을 변경할 수 있도록 하는 커널 기술입니다.  일단 특정 이벤트가 eBPF 프로그램에 연결(attach)되면, 해당 이벤트가 발생할 때마다 그 원인과 관계없이 자동으로 eBPF프로그램이 실행됩니다.

애플리케이션은 커널을 통해서만 하드웨어에 접근할 수 있기 때문에, 애플리케이션이 커널과 상호작용하는 방식을 관찰하면 해당 애플리케이션의 동작을 계측 및 제어할 수 있습니다.

예를 들어 애플리케이션에서 발생하는 아웃바운드 패킷을 가로챌 수 있다면, 어떤 애플리케이션이 어떤  패킷을 어디로 전송하는지 정확히 확인 및 제어가 가능합니다.

![eBPF in Kernel](/assets/img/posts/2025-01-21-Cilium으로%20구현하는%20FQDN%20기반%20Kubernetes%20네트워크%20정책/eBPF-in-kernel.png)
_eBPF in Kernel (출처: [Learning eBPF](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf))_


> 💡 **Note**  
> 커널 내에는 eBPF프로그램이 연결될 수 있는 많은 attach points가 있습니다.    
> 현재 최신버전 기준 uapi/linux/bpf.h 파일에는 약 30가지의 eBPF 프로그램 유형과 40가지 이상의 attachment types가 정의되어 있습니다.

### Cilium 내부에서 동작하는 다양한 eBPF 프로그램의 역할

Cilium은 커널 및 네트워크 스택의 여러 부분에 연결(ePBF hook)되는 다양한 eBPF 프로그램들로 구성됩니다.

![cilium and eBPF](/assets/img/posts/2025-01-21-Cilium으로%20구현하는%20FQDN%20기반%20Kubernetes%20네트워크%20정책/cilium-and-eBPF.png)
_cilium and eBPF (출처: [Learning eBPF](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf))_

패킷이 어디로 향하는지에 따라 서로 다른 eBPF 프로그램이 호출됩니다. 예를 들면 다음과 같습니다.

- 로컬 컨테이너(Pod)로 가는 트래픽
- 로컬 호스트로 향하는 트래픽
- 같은 네트워크에 있는 다른 호스트로 가는 트래픽
- 터널을 통해 전달되는 트래픽

이처럼 Cilium은 다양한 eBPF 프로그램을 활용하여 네트워크 환경과 트래픽의 종류에 따라 적절한 처리를 수행합니다.

### Life of Egress Packet

Pod에서 발생한 egress 패킷이 처리되는 과정을 eBPF datapath 관점에서 도식화한 차트입니다.

![life of egress packet](/assets/img/posts/2025-01-21-Cilium으로%20구현하는%20FQDN%20기반%20Kubernetes%20네트워크%20정책/life-of-egress-packet.png)
_life of egress packet (출처: [Life of a packet](https://docs.cilium.io/en/stable/network/ebpf/lifeofapacket/))_

패킷이 커널의 Traffic Control에 도착하면 Cilium이 로드한 bpf_lxc eBPF 프로그램 호출됩니다. 앞서 DNS 쿼리 요청을 '가로채고' DNS Proxy에 '리디렉션' 하는 역할을 이 bpf_lxc eBPF 프로그램이 수행합니다. 

> 💡 **Note**   
> 해당 차트의 출처는 Cilium 공식 문서이며, 공식 문서 에서는 egress 뿐만 아니라 다양한 시나리오에 대한 life of packet을 설명하고 있습니다. [life of packet](https://docs.cilium.io/en/stable/network/ebpf/lifeofapacket/)

# 결론

이번 글에서는 Cilium을 활용한 FQDN 기반 egress 네트워크 정책 적용 방법과 이를 가능하게 하는 eBPF 기술의 원리를 살펴보았습니다.  Cilium은 DNS 쿼리를 가로채고 FQDN-IP 매핑을 동적으로 관리 하여 보다 유연한 트래픽 제어를 가능하게 합니다.

특히, eBPF를 활용하여 커널 수준에서 패킷을 처리함으로써 고성능 네트워크 정책 적용이 가능하며, 이를 통해 보안과 운영 효율성을 동시에 향상시킬 수 있습니다.

FQDN 필터링은 Cilium이 제공하는 다양한 기능 중 일부에 불과합니다. Cilium은 네트워크 보안, 로드 밸런싱, 서비스 메시 등 Kubernetes 네트워킹을 더욱 강력하게 확장할 수 있는 기능들을 포함하고 있습니다. 따라서 Cilium을 활용하면 Kubernetes 환경에서 보다 정교한 네트워크 제어와 보안 정책을 적용할 수 있습니다.

# 참고
---
[cilium.io](https://cilium.io/)   
[What is Advanced Container Networking Services?](https://learn.microsoft.com/en-us/azure/aks/advanced-container-networking-services-overview?tabs=cilium)  
[Learning eBPF - Full book](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf) 

