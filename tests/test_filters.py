"""
测试 filters.py 的过滤功能
"""
import pytest
from dataclasses import dataclass

from subio_v2.workflow.filters import (
    regex_filter,
    exclude,
    hk_filter,
    tw_filter,
    sg_filter,
    jp_filter,
    kr_filter,
    us_filter,
    keyWord_filter,
    combine,
    all_filters,
    # 新 API
    F,
    keyword,
    regex,
    excluding,
    union,
    intersect,
    chain,
)


@dataclass(frozen=True)
class MockNode:
    """模拟节点对象（frozen 使其可哈希）"""
    name: str


class TestGetName:
    """测试名称获取逻辑"""

    def test_string_input(self):
        """字符串直接返回"""
        result = regex_filter(["香港节点", "日本节点"], "香港")
        assert "香港节点" in result

    def test_object_with_name(self):
        """对象使用 .name 属性"""
        nodes = [MockNode("香港节点"), MockNode("日本节点")]
        result = regex_filter(nodes, "香港")
        assert len(result) == 1
        assert result[0].name == "香港节点"


class TestRegexFilter:
    """测试正则过滤"""

    def test_basic_match(self):
        data = ["香港-01", "日本-01", "香港-02"]
        result = regex_filter(data, "香港")
        assert result == ["香港-01", "香港-02"]

    def test_case_insensitive(self):
        """测试大小写不敏感"""
        data = ["HK-01", "hk-02", "JP-01"]
        result = regex_filter(data, "hk")
        assert len(result) == 2
        assert "HK-01" in result
        assert "hk-02" in result

    def test_regex_pattern(self):
        """测试正则表达式"""
        data = ["node-1", "node-2", "server-1"]
        result = regex_filter(data, r"node-\d")
        assert result == ["node-1", "node-2"]

    def test_no_match(self):
        """无匹配返回空列表"""
        data = ["香港-01", "日本-01"]
        result = regex_filter(data, "美国")
        assert result == []

    def test_empty_data(self):
        """空数据返回空列表"""
        result = regex_filter([], "香港")
        assert result == []


class TestExclude:
    """测试排除过滤"""

    def test_basic_exclude(self):
        data = ["香港-01", "日本-01", "香港-02"]
        result = exclude(data, "香港")
        assert result == ["日本-01"]

    def test_exclude_case_insensitive(self):
        data = ["HK-01", "hk-02", "JP-01"]
        result = exclude(data, "hk")
        assert result == ["JP-01"]

    def test_exclude_nothing(self):
        """无匹配时返回全部"""
        data = ["香港-01", "日本-01"]
        result = exclude(data, "美国")
        assert result == data


class TestRegionFilters:
    """测试地区过滤器"""

    def test_hk_filter(self):
        data = ["香港-01", "HK-02", "Hong Kong-03", "日本-01"]
        result = hk_filter(data)
        assert len(result) == 3
        assert "日本-01" not in result

    def test_tw_filter(self):
        data = ["台湾-01", "TW-02", "Taiwan-03", "日本-01"]
        result = tw_filter(data)
        assert len(result) == 3
        assert "日本-01" not in result

    def test_sg_filter(self):
        data = ["新加坡-01", "SG-02", "Singapore-03", "日本-01"]
        result = sg_filter(data)
        assert len(result) == 3
        assert "日本-01" not in result

    def test_jp_filter(self):
        data = ["日本-01", "JP-02", "Japan-03", "香港-01"]
        result = jp_filter(data)
        assert len(result) == 3
        assert "香港-01" not in result

    def test_kr_filter(self):
        data = ["韩国-01", "KR-02", "Korea-03", "日本-01"]
        result = kr_filter(data)
        assert len(result) == 3
        assert "日本-01" not in result

    def test_us_filter(self):
        data = ["美国-01", "US-02", "United States-03", "USA-04", "日本-01"]
        result = us_filter(data)
        assert len(result) == 4
        assert "日本-01" not in result


class TestKeyWordFilter:
    """测试关键词过滤"""

    def test_keyword_filter(self):
        data = ["premium-hk", "standard-hk", "premium-jp"]
        result = keyWord_filter(data, "premium")
        assert result == ["premium-hk", "premium-jp"]


class TestCombine:
    """测试组合过滤"""

    def test_union_default(self):
        """默认并集（OR）"""
        data = ["香港-01", "日本-01", "美国-01", "韩国-01"]
        result = combine(data, hk_filter, jp_filter)
        assert len(result) == 2
        assert "香港-01" in result
        assert "日本-01" in result

    def test_intersection(self):
        """交集（AND）"""
        data = ["香港-premium", "香港-standard", "日本-premium"]
        result = combine(
            data,
            hk_filter,
            keyWord_filter,
            left_args=None,
            right_args="premium",
            relation=True,
        )
        assert len(result) == 1
        assert "香港-premium" in result

    def test_union_with_args(self):
        """带参数的并集"""
        data = ["香港-01", "日本-01", "美国-01"]
        result = combine(
            data,
            keyWord_filter,
            keyWord_filter,
            left_args="香港",
            right_args="美国",
            relation=False,
        )
        assert len(result) == 2
        assert "香港-01" in result
        assert "美国-01" in result


class TestFilterCollection:
    """测试 FilterCollection 类"""

    def test_all_filters_has_methods(self):
        """验证 all_filters 包含所有过滤方法"""
        assert hasattr(all_filters, "hk_filter")
        assert hasattr(all_filters, "tw_filter")
        assert hasattr(all_filters, "sg_filter")
        assert hasattr(all_filters, "jp_filter")
        assert hasattr(all_filters, "kr_filter")
        assert hasattr(all_filters, "us_filter")
        assert hasattr(all_filters, "keyWord_filter")
        assert hasattr(all_filters, "regex_filter")
        assert hasattr(all_filters, "exclude")
        assert hasattr(all_filters, "combine")

    def test_all_filters_callable(self):
        """验证方法可调用"""
        data = ["香港-01", "日本-01"]
        result = all_filters.hk_filter(data)
        assert "香港-01" in result

    def test_all_filters_combine(self):
        """测试通过 all_filters 调用 combine"""
        data = ["香港-01", "日本-01", "美国-01"]
        result = all_filters.combine(
            data,
            all_filters.hk_filter,
            all_filters.jp_filter,
        )
        assert len(result) == 2


class TestWithMockNodes:
    """测试使用模拟节点对象"""

    def test_filter_nodes(self):
        """测试过滤节点对象"""
        nodes = [
            MockNode("香港-IPLC-01"),
            MockNode("香港-普通-02"),
            MockNode("日本-01"),
            MockNode("美国-01"),
        ]
        
        # 过滤香港节点
        hk_nodes = hk_filter(nodes)
        assert len(hk_nodes) == 2
        assert all("香港" in n.name for n in hk_nodes)

    def test_exclude_nodes(self):
        """测试排除节点对象"""
        nodes = [
            MockNode("香港-01"),
            MockNode("日本-01"),
            MockNode("剩余流量: 100GB"),
        ]
        
        # 排除流量信息节点
        result = exclude(nodes, "剩余流量")
        assert len(result) == 2
        assert all("剩余流量" not in n.name for n in result)

    def test_combine_nodes(self):
        """测试组合过滤节点对象"""
        nodes = [
            MockNode("香港-IPLC"),
            MockNode("香港-普通"),
            MockNode("日本-IPLC"),
            MockNode("日本-普通"),
        ]
        
        # 香港 AND IPLC
        result = combine(
            nodes,
            hk_filter,
            keyWord_filter,
            right_args="IPLC",
            relation=True,
        )
        assert len(result) == 1
        assert result[0].name == "香港-IPLC"


# ============== 新 API 测试 ==============

class TestFactoryFunctions:
    """测试工厂函数"""

    def test_keyword(self):
        """测试 keyword 工厂"""
        data = ["premium-hk", "standard-hk", "premium-jp"]
        result = keyword("premium")(data)
        assert result == ["premium-hk", "premium-jp"]

    def test_regex(self):
        """测试 regex 工厂"""
        data = ["node-1", "node-2", "server-1"]
        result = regex(r"node-\d")(data)
        assert result == ["node-1", "node-2"]

    def test_excluding(self):
        """测试 excluding 工厂"""
        data = ["香港-01", "日本-01", "剩余流量"]
        result = excluding("剩余流量")(data)
        assert len(result) == 2
        assert "剩余流量" not in result


class TestUnion:
    """测试 union 组合器"""

    def test_union_two(self):
        """并集两个过滤器"""
        data = ["香港-01", "日本-01", "美国-01", "韩国-01"]
        result = union(F.hk, F.jp)(data)
        assert len(result) == 2
        assert "香港-01" in result
        assert "日本-01" in result

    def test_union_multiple(self):
        """并集多个过滤器"""
        data = ["香港-01", "日本-01", "美国-01", "韩国-01"]
        result = union(F.hk, F.jp, F.us)(data)
        assert len(result) == 3
        assert "韩国-01" not in result

    def test_union_empty(self):
        """空过滤器列表返回原数据"""
        data = ["香港-01", "日本-01"]
        result = union()(data)
        assert result == data


class TestIntersect:
    """测试 intersect 组合器"""

    def test_intersect_basic(self):
        """交集过滤"""
        data = ["香港-IPLC", "香港-普通", "日本-IPLC", "日本-普通"]
        result = intersect(F.hk, keyword("IPLC"))(data)
        assert len(result) == 1
        assert "香港-IPLC" in result

    def test_intersect_multiple(self):
        """多个过滤器交集"""
        data = ["香港-IPLC-premium", "香港-IPLC-standard", "香港-普通-premium"]
        result = intersect(F.hk, keyword("IPLC"), keyword("premium"))(data)
        assert len(result) == 1
        assert "香港-IPLC-premium" in result

    def test_intersect_empty(self):
        """空过滤器列表返回原数据"""
        data = ["香港-01", "日本-01"]
        result = intersect()(data)
        assert result == data


class TestChain:
    """测试 chain 组合器"""

    def test_chain_basic(self):
        """链式过滤"""
        data = ["香港-IPLC", "香港-普通", "日本-IPLC", "日本-普通"]
        # 先选香港，再排除普通
        result = chain(F.hk, excluding("普通"))(data)
        assert len(result) == 1
        assert "香港-IPLC" in result

    def test_chain_multiple(self):
        """多步链式过滤"""
        data = ["香港-IPLC-A", "香港-IPLC-B", "香港-普通", "日本-IPLC"]
        result = chain(F.hk, keyword("IPLC"), excluding("B"))(data)
        assert len(result) == 1
        assert "香港-IPLC-A" in result


class TestFClass:
    """测试 F 快捷类"""

    def test_f_direct_call(self):
        """直接调用 F.xxx"""
        data = ["香港-01", "日本-01"]
        result = F.hk(data)
        assert "香港-01" in result
        assert "日本-01" not in result

    def test_f_with_union(self):
        """F 与 union 组合"""
        data = ["香港-01", "日本-01", "美国-01"]
        result = union(F.hk, F.jp)(data)
        assert len(result) == 2

    def test_f_all_regions(self):
        """测试所有地区"""
        assert callable(F.hk)
        assert callable(F.tw)
        assert callable(F.sg)
        assert callable(F.jp)
        assert callable(F.kr)
        assert callable(F.us)


class TestNewAPIWithMockNodes:
    """测试新 API 与节点对象"""

    def test_union_nodes(self):
        nodes = [
            MockNode("香港-01"),
            MockNode("日本-01"),
            MockNode("美国-01"),
        ]
        result = union(F.hk, F.jp)(nodes)
        names = [n.name for n in result]
        assert "香港-01" in names
        assert "日本-01" in names

    def test_intersect_nodes(self):
        nodes = [
            MockNode("香港-IPLC"),
            MockNode("香港-普通"),
            MockNode("日本-IPLC"),
        ]
        result = intersect(F.hk, keyword("IPLC"))(nodes)
        assert len(result) == 1
        assert result[0].name == "香港-IPLC"

    def test_chain_nodes(self):
        nodes = [
            MockNode("香港-IPLC"),
            MockNode("香港-普通"),
            MockNode("日本-01"),
        ]
        result = chain(F.hk, excluding("普通"))(nodes)
        assert len(result) == 1
        assert result[0].name == "香港-IPLC"

